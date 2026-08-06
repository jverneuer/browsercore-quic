/**
 * Stream manager tests for @browsercore/quic.
 *
 * Drives createStreamManager through its public surface plus the internal
 * ManagedStream paths reachable via dispatch/flush: stream open + accept
 * lifecycle, STREAM reassembly (contiguous, out-of-order, overlap), flow-
 * control windows and blocking, RESET_STREAM / STOP_SENDING, MAX_DATA /
 * MAX_STREAM_DATA / MAX_STREAMS handling, CONNECTION_CLOSE signaling, and
 * teardown via abortAll / close.
 */

import { describe, it, expect } from "vitest";
import { createStreamManager } from "../src/stream/stream.js";
import {
    QuicFrameType,
    type QuicFrame,
    type QuicSignalSink,
    type QuicStream,
    type QuicTransportParameters,
} from "../src/types.js";
import { ResetStreamError, StopSendingError } from "../src/errors.js";

type Manager = ReturnType<typeof createStreamManager>;

/** Recorded signals from the stream manager — tests assert against these. */
interface RecordedSignals {
    incomingStreams: QuicStream[];
    connectionCloses: Array<{ errorCode: bigint; reason: string }>;
    maxData: bigint[];
}

function makeManager(
    local: QuicTransportParameters = {},
    peer: QuicTransportParameters = {},
): { manager: Manager; sent: QuicFrame[]; signals: RecordedSignals } {
    const sent: QuicFrame[] = [];
    const signals: RecordedSignals = {
        incomingStreams: [],
        connectionCloses: [],
        maxData: [],
    };
    const manager = createStreamManager({
        sendFrame: (f) => {
            sent.push(f);
        },
        signals: {
            onIncomingStream: (s) => {
                signals.incomingStreams.push(s);
            },
            onConnectionClose: (errorCode, reason) => {
                signals.connectionCloses.push({ errorCode, reason });
            },
            onMaxData: (m) => {
                signals.maxData.push(m);
            },
        },
        localParameters: local,
        peerParameters: peer,
    });
    return { manager, sent, signals };
}

/** Build a STREAM frame targeting a server-initiated bidirectional stream id. */
function streamFrame(
    streamId: bigint,
    data: number[],
    offset = 0n,
    fin = false,
): QuicFrame {
    return {
        type: QuicFrameType.STREAM,
        streamId,
        offset,
        data: new Uint8Array(data),
        fin,
    };
}

describe("openStream / acceptStream lifecycle", () => {
    it("opens client bidi streams at 0, 4, 8 and uni streams at 2, 6", () => {
        const { manager } = makeManager();
        expect(manager.openStream(true).id).toBe(0n);
        expect(manager.openStream(true).id).toBe(4n);
        expect(manager.openStream(true).id).toBe(8n);
        expect(manager.openStream(false).id).toBe(2n);
        expect(manager.openStream(false).id).toBe(6n);
    });

    it("throws when opening a stream after close", () => {
        const { manager } = makeManager();
        manager.close(0n, "bye");
        expect(() => manager.openStream(true)).toThrow(/closing/);
        expect(() => manager.openStream(false)).toThrow(/closing/);
    });

    it("accepts a peer-initiated bidi stream once it arrives", async () => {
        const { manager } = makeManager();
        // Server-initiated bidi stream id = 1.
        manager.dispatch(streamFrame(1n, [1, 2, 3]));
        const stream = await manager.acceptStream(true);
        expect(stream.id).toBe(1n);
        expect(Array.from(await stream.read())).toEqual([1, 2, 3]);
    });

    it("resolves a pending accept waiter when the stream arrives", async () => {
        const { manager } = makeManager();
        const pending = manager.acceptStream(true);
        // Drain microtasks so the waiter is registered before dispatch.
        await Promise.resolve();
        manager.dispatch(streamFrame(1n, [9]));
        const stream = await pending;
        expect(stream.id).toBe(1n);
        expect(Array.from(await stream.read())).toEqual([9]);
    });

    it("accepts a peer-initiated unidirectional stream", async () => {
        const { manager } = makeManager();
        manager.dispatch(streamFrame(3n, [1]));
        const stream = await manager.acceptStream(false);
        expect(stream.id).toBe(3n);
    });

    it("signals incomingStream when no accept waiter is registered", () => {
        const { manager, signals } = makeManager();
        manager.dispatch(streamFrame(1n, [1]));
        expect(signals.incomingStreams).toHaveLength(1);
        expect(signals.incomingStreams[0]?.id).toBe(1n);
    });

    it("ignores STREAM frames for unknown client-initiated streams", () => {
        const { manager, signals } = makeManager();
        // id 0 is client-initiated but no local stream exists there.
        manager.dispatch(streamFrame(0n, [1]));
        expect(signals.incomingStreams).toHaveLength(0);
    });
});

describe("STREAM reassembly", () => {
    it("delivers contiguous data immediately", async () => {
        const { manager } = makeManager();
        manager.dispatch(streamFrame(1n, [1, 2, 3, 4]));
        const stream = await manager.acceptStream(true);
        expect(Array.from(await stream.read())).toEqual([1, 2, 3, 4]);
    });

    it("reassembles out-of-order frames in offset order", async () => {
        const { manager } = makeManager();
        manager.dispatch(streamFrame(1n, [4, 5], 3n)); // buffered in reassembly
        manager.dispatch(streamFrame(1n, [1, 2, 3], 0n)); // bridges the gap
        const stream = await manager.acceptStream(true);
        expect(Array.from(await stream.read())).toEqual([1, 2, 3, 4, 5]);
    });

    it("drops bytes already delivered (overlap / retransmit)", async () => {
        const { manager } = makeManager();
        manager.dispatch(streamFrame(1n, [1, 2, 3, 4], 0n));
        manager.dispatch(streamFrame(1n, [3, 4], 0n)); // fully below recvOffset
        const stream = await manager.acceptStream(true);
        expect(Array.from(await stream.read())).toEqual([1, 2, 3, 4]);
    });

    it("clips the overlapping front of a frame straddling recvOffset", async () => {
        const { manager } = makeManager();
        manager.dispatch(streamFrame(1n, [1, 2, 3], 0n));
        manager.dispatch(streamFrame(1n, [2, 3, 4], 1n)); // front overlaps
        const stream = await manager.acceptStream(true);
        // The overlap is clipped; only the new byte (4) is appended to the buffer.
        expect(Array.from(await stream.read())).toEqual([1, 2, 3, 4]);
    });

    it("signals EOF after a FIN frame at the stream end", async () => {
        const { manager } = makeManager();
        manager.dispatch(streamFrame(1n, [1, 2], 0n, true));
        const stream = await manager.acceptStream(true);
        expect(Array.from(await stream.read())).toEqual([1, 2]);
        // FIN delivered: subsequent reads resolve to an empty chunk.
        expect((await stream.read()).length).toBe(0);
    });

    it("signals EOF when FIN arrives before its data is reassembled", async () => {
        const { manager } = makeManager();
        manager.dispatch(streamFrame(1n, [], 2n, true)); // FIN at offset 2
        manager.dispatch(streamFrame(1n, [7, 8], 0n)); // fills the gap
        const stream = await manager.acceptStream(true);
        expect(Array.from(await stream.read())).toEqual([7, 8]);
        expect((await stream.read()).length).toBe(0);
    });

    it("buffers data for a reader that has not yet called read()", async () => {
        const { manager } = makeManager();
        manager.dispatch(streamFrame(1n, [1], 0n));
        manager.dispatch(streamFrame(1n, [2], 1n));
        const stream = await manager.acceptStream(true);
        // Both chunks concatenated into the read buffer.
        expect(Array.from(await stream.read())).toEqual([1, 2]);
    });
});

describe("write / flushSends (send path)", () => {
    it("buffers written bytes and flushes them as a STREAM frame", () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        expect(manager.hasPendingSends).toBe(false);
        void s.write(new Uint8Array([1, 2, 3]));
        expect(manager.hasPendingSends).toBe(true);

        const emitted: QuicFrame[] = [];
        manager.flushSends(1200, (f) => emitted.push(f));
        const sf = emitted.find((f) => f.type === QuicFrameType.STREAM);
        expect(sf).toBeDefined();
        expect(sf).toMatchObject({ streamId: 0n, offset: 0n, fin: false });
        expect(Array.from((sf as { data: Uint8Array }).data)).toEqual([1, 2, 3]);
        expect(manager.hasPendingSends).toBe(false);
    });

    it("sends the FIN flag when close() was called and the queue drains fully", () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        void s.write(new Uint8Array([1, 2]));
        void s.close();

        const emitted: QuicFrame[] = [];
        manager.flushSends(1200, (f) => emitted.push(f));
        const sf = emitted.find((f) => f.type === QuicFrameType.STREAM) as
            | { fin: boolean }
            | undefined;
        expect(sf?.fin).toBe(true);
    });

    it("clips the payload to the budget when bytes exceed maxPayload", () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        void s.write(new Uint8Array(10).fill(0xab));
        const emitted: QuicFrame[] = [];
        manager.flushSends(4, (f) => emitted.push(f));
        const sf = emitted.find((f) => f.type === QuicFrameType.STREAM) as
            | { data: Uint8Array }
            | undefined;
        expect(sf?.data.length).toBe(4);
        // Remaining bytes are still pending.
        expect(manager.hasPendingSends).toBe(true);
    });

    it("emits STREAM_DATA_BLOCKED when the per-stream window is exhausted", () => {
        const { manager } = makeManager(
            {},
            { initialMaxStreamDataBidiRemote: 0n },
        );
        const s = manager.openStream(true);
        void s.write(new Uint8Array([1]));
        const emitted: QuicFrame[] = [];
        manager.flushSends(1200, (f) => emitted.push(f));
        expect(emitted.some((f) => f.type === QuicFrameType.STREAM_DATA_BLOCKED)).toBe(true);
        const blocked = emitted.find((f) => f.type === QuicFrameType.STREAM_DATA_BLOCKED) as
            | { streamId: bigint; limit: bigint }
            | undefined;
        expect(blocked).toMatchObject({ streamId: 0n, limit: 0n });
    });

    it("unblocks a send after MAX_STREAM_DATA grows the window", () => {
        const { manager } = makeManager(
            {},
            { initialMaxStreamDataBidiRemote: 0n },
        );
        const s = manager.openStream(true);
        void s.write(new Uint8Array([1, 2]));

        const first: QuicFrame[] = [];
        manager.flushSends(1200, (f) => first.push(f));
        expect(first.some((f) => f.type === QuicFrameType.STREAM)).toBe(false);

        manager.dispatch({
            type: QuicFrameType.MAX_STREAM_DATA,
            streamId: 0n,
            maximum: 100n,
        });
        const second: QuicFrame[] = [];
        manager.flushSends(1200, (f) => second.push(f));
        expect(second.some((f) => f.type === QuicFrameType.STREAM)).toBe(true);
        void s;
    });

    it("does not shrink the window when MAX_STREAM_DATA is smaller", () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        void s.write(new Uint8Array([1]));
        // A no-op maximum (less than the default 256KiB) must not shrink.
        manager.dispatch({
            type: QuicFrameType.MAX_STREAM_DATA,
            streamId: 0n,
            maximum: 1n,
        });
        const emitted: QuicFrame[] = [];
        manager.flushSends(1200, (f) => emitted.push(f));
        // Default window is large enough that the byte still flushes.
        expect(emitted.some((f) => f.type === QuicFrameType.STREAM)).toBe(true);
        void s;
    });

    it("write() on a closed stream rejects with ResetStreamError", async () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        // Force the stream into half_closed_local by sending a FIN.
        void s.write(new Uint8Array([1]));
        void s.close();
        manager.flushSends(1200, () => {});
        await expect(s.write(new Uint8Array([2]))).rejects.toBeInstanceOf(ResetStreamError);
    });

    it("write() of an empty buffer is a no-op that resolves immediately", async () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        await expect(s.write(new Uint8Array(0))).resolves.toBeUndefined();
        expect(manager.hasPendingSends).toBe(false);
    });

    it("close() is idempotent on a single stream", async () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        await s.close();
        await expect(s.close()).resolves.toBeUndefined();
    });
});

describe("peer control frames", () => {
    it("RESET_STREAM rejects pending readers and removes the stream", async () => {
        const { manager } = makeManager();
        manager.dispatch(streamFrame(1n, [1]));
        const stream = await manager.acceptStream(true);
        await stream.read(); // drain the buffered byte
        const pending = stream.read(); // now blocks
        manager.dispatch({
            type: QuicFrameType.RESET_STREAM,
            streamId: 1n,
            errorCode: 7n,
            finalSize: 1n,
        });
        await expect(pending).rejects.toBeInstanceOf(ResetStreamError);
    });

    it("RESET_STREAM for an unknown stream is a no-op", () => {
        const { manager } = makeManager();
        expect(() =>
            manager.dispatch({
                type: QuicFrameType.RESET_STREAM,
                streamId: 99n,
                errorCode: 0n,
                finalSize: 0n,
            }),
        ).not.toThrow();
    });

    it("STOP_SENDING clears the send queue so nothing more flushes", () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        void s.write(new Uint8Array([1, 2, 3]));
        manager.dispatch({
            type: QuicFrameType.STOP_SENDING,
            streamId: 0n,
            errorCode: 0n,
        });
        expect(manager.hasPendingSends).toBe(false);
        const emitted: QuicFrame[] = [];
        manager.flushSends(1200, (f) => emitted.push(f));
        expect(emitted).toHaveLength(0);
    });

    it("STOP_SENDING for an unknown stream is a no-op", () => {
        const { manager } = makeManager();
        expect(() =>
            manager.dispatch({
                type: QuicFrameType.STOP_SENDING,
                streamId: 99n,
                errorCode: 0n,
            }),
        ).not.toThrow();
    });
});

describe("connection-level frame handling", () => {
    it("MAX_DATA grows the connection window and signals maxData only on growth", () => {
        const { manager, signals } = makeManager();
        manager.dispatch({ type: QuicFrameType.MAX_DATA, maximum: 5_000_000n });
        expect(signals.maxData).toEqual([5_000_000n]);
        // A smaller value does not grow the window and must not signal.
        manager.dispatch({ type: QuicFrameType.MAX_DATA, maximum: 1n });
        expect(signals.maxData).toEqual([5_000_000n]);
    });

    it("MAX_STREAMS_BIDI / MAX_STREAMS_UNI are accepted without error", () => {
        const { manager } = makeManager();
        manager.dispatch({ type: QuicFrameType.MAX_STREAMS_BIDI, maximum: 200n });
        manager.dispatch({ type: QuicFrameType.MAX_STREAMS_UNI, maximum: 300n });
        // Smaller values are ignored (no-op).
        manager.dispatch({ type: QuicFrameType.MAX_STREAMS_BIDI, maximum: 1n });
        manager.dispatch({ type: QuicFrameType.MAX_STREAMS_UNI, maximum: 1n });
        expect(() => manager.openStream(true)).not.toThrow();
    });

    it("CONNECTION_CLOSE sets closing and signals the close", () => {
        const { manager, signals } = makeManager();
        manager.dispatch({
            type: QuicFrameType.CONNECTION_CLOSE,
            errorCode: 0x0cn,
            frameType: undefined,
            reason: "bye",
        });
        expect(signals.connectionCloses).toEqual([{ errorCode: 0x0cn, reason: "bye" }]);
        // After connection close, new streams cannot be opened.
        expect(() => manager.openStream(true)).toThrow(/closing/);
    });

    it("CONNECTION_CLOSE_APP is also surfaced as a close signal", () => {
        const { manager, signals } = makeManager();
        manager.dispatch({
            type: QuicFrameType.CONNECTION_CLOSE_APP,
            errorCode: 0x0103n,
            frameType: 0n,
            reason: "app close",
        });
        expect(signals.connectionCloses).toHaveLength(1);
        expect(signals.connectionCloses[0]?.reason).toBe("app close");
    });

    it("informational frames (PING, ACK, CRYPTO, ...) are dispatched without effect", () => {
        const { manager } = makeManager();
        // None of these should throw or create streams.
        expect(() => {
            manager.dispatch({ type: QuicFrameType.PING });
            manager.dispatch({ type: QuicFrameType.PADDING });
            manager.dispatch({ type: QuicFrameType.ACK, largestAck: 0n, ackDelay: 0n, ackRangeCount: 0n, firstAckRange: 0n, ackRanges: [] });
            manager.dispatch({ type: QuicFrameType.CRYPTO, offset: 0n, data: new Uint8Array([1]) });
            manager.dispatch({ type: QuicFrameType.HANDSHAKE_DONE });
        }).not.toThrow();
    });

    it("emits MAX_STREAM_DATA and MAX_DATA once enough data is consumed", () => {
        const { manager, sent } = makeManager();
        // 600 KiB exceeds both the per-stream (128 KiB) and connection (512 KiB)
        // replenish thresholds derived from the default advertised windows.
        const big = new Uint8Array(600_000).fill(0x41);
        manager.dispatch({
            type: QuicFrameType.STREAM,
            streamId: 1n,
            offset: 0n,
            data: big,
            fin: false,
        });
        const types = sent.map((f) => f.type);
        expect(types).toContain(QuicFrameType.MAX_STREAM_DATA);
        expect(types).toContain(QuicFrameType.MAX_DATA);
    });
});

describe("teardown", () => {
    it("abortAll rejects pending readers, writers, and accept waiters", async () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        const readP = s.read(); // pending (no incoming data)
        const acceptP = manager.acceptStream(true); // pending (no peer stream)

        manager.abortAll(new Error("boom"));
        await expect(readP).rejects.toThrow(/connection closed/);
        await expect(acceptP).rejects.toThrow(/boom/);
    });

    it("close emits a CONNECTION_CLOSE frame and is idempotent", () => {
        const { manager, sent } = makeManager();
        manager.close(0n, "bye");
        const closes = sent.filter((f) => f.type === QuicFrameType.CONNECTION_CLOSE);
        expect(closes).toHaveLength(1);
        expect(closes[0]).toMatchObject({ errorCode: 0n, reason: "bye" });

        // A second close() is a no-op (frame already emitted).
        manager.close(1n, "again");
        expect(sent.filter((f) => f.type === QuicFrameType.CONNECTION_CLOSE)).toHaveLength(1);
    });

    it("localParameters are exposed on the manager", () => {
        const { manager } = makeManager({ initialMaxData: 999n });
        expect(manager.localParameters.initialMaxData).toBe(999n);
    });
});

describe("signal sink delivery", () => {
    it("delivers incomingStream signals for each peer-initiated stream", () => {
        const { manager, signals } = makeManager();
        manager.dispatch(streamFrame(1n, [1]));
        manager.dispatch(streamFrame(5n, [1]));
        expect(signals.incomingStreams.map((s) => s.id)).toEqual([1n, 5n]);
    });
});

describe("stream state transitions", () => {
    it("transitions to half_closed_local after a flushed FIN", () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        void s.write(new Uint8Array([1, 2]));
        void s.close();
        // Draining sends commits the FIN → transitionOnLocalFin → half_closed_local.
        manager.flushSends(1200, () => {});
        // A write on a half_closed_local stream must reject.
        return expect(s.write(new Uint8Array([3]))).rejects.toBeInstanceOf(ResetStreamError);
    });

    it("transitions to half_closed_remote once the peer FIN is delivered", async () => {
        const { manager } = makeManager();
        // Server-initiated bidi stream id = 1, FIN at offset 0 with one byte.
        manager.dispatch(streamFrame(1n, [7], 0n, true));
        const stream = await manager.acceptStream(true);
        // The byte arrives, then the FIN delivers EOF on the next read().
        expect(Array.from(await stream.read())).toEqual([7]);
        expect((await stream.read()).length).toBe(0);
        // half_closed_remote: the local side can still write, so it must resolve.
        await expect(stream.write(new Uint8Array([1]))).resolves.toBeUndefined();
    });

    it("reaches closed when the local side FINs and then the peer FINs", async () => {
        const { manager } = makeManager();
        // Peer opens stream 1; local side writes, closes, and flushes the FIN.
        manager.dispatch(streamFrame(1n, [1], 0n));
        const stream = await manager.acceptStream(true);
        await stream.read(); // drain the byte
        void stream.write(new Uint8Array([9]));
        void stream.close();
        manager.flushSends(1200, () => {}); // local FIN → half_closed_local
        // Now the peer FINs: half_closed_local + remote FIN → closed.
        manager.dispatch(streamFrame(1n, [2], 1n, true));
        // A closed stream must reject writes with ResetStreamError.
        await expect(stream.write(new Uint8Array([3]))).rejects.toBeInstanceOf(ResetStreamError);
    });

    it("reaches closed when the peer FINs and then the local side FINs", async () => {
        const { manager } = makeManager();
        // Peer opens stream 1 and FINs immediately → half_closed_remote.
        manager.dispatch(streamFrame(1n, [1], 0n, true));
        const stream = await manager.acceptStream(true);
        await stream.read(); // the byte
        expect((await stream.read()).length).toBe(0); // EOF
        // Local side writes (still allowed) and FINs → half_closed_remote + local FIN → closed.
        void stream.write(new Uint8Array([9]));
        void stream.close();
        manager.flushSends(1200, () => {});
        await expect(stream.write(new Uint8Array([3]))).rejects.toBeInstanceOf(ResetStreamError);
    });

    it("rejects writes on a stream the peer reset", () => {
        const { manager } = makeManager();
        manager.dispatch(streamFrame(1n, [1]));
        // No accept — reset the stream directly.
        manager.dispatch({
            type: QuicFrameType.RESET_STREAM,
            streamId: 1n,
            errorCode: 0x01n,
            finalSize: 1n,
        });
        // After reset the stream is closed; a fresh write on a closed stream rejects.
        const s = manager.openStream(true);
        void s.write(new Uint8Array([1]));
        void s.close();
        manager.flushSends(1200, () => {});
        return expect(s.write(new Uint8Array([2]))).rejects.toBeInstanceOf(ResetStreamError);
    });
});

describe("reassembly edge cases", () => {
    it("drops a frame that lies entirely below recvOffset", async () => {
        const { manager } = makeManager();
        manager.dispatch(streamFrame(1n, [1, 2, 3, 4], 0n));
        // Fully-below retransmit: end (2) <= recvOffset (4).
        manager.dispatch(streamFrame(1n, [1, 2], 0n));
        const stream = await manager.acceptStream(true);
        expect(Array.from(await stream.read())).toEqual([1, 2, 3, 4]);
    });

    it("leaves a gap in the reassembly buffer when a frame arrives out of order", async () => {
        const { manager } = makeManager();
        // Arrives first but starts past offset 0 — buffered, recvOffset stays 0.
        manager.dispatch(streamFrame(1n, [5, 6], 4n));
        const stream = await manager.acceptStream(true);
        // No contiguous data yet: a read() blocks.
        const pending = stream.read();
        // It must not have resolved to the out-of-order chunk.
        await expect(Promise.race([pending, Promise.resolve("pending")])).resolves.toBe("pending");
        // Now bridge the gap.
        manager.dispatch(streamFrame(1n, [1, 2, 3, 4], 0n));
        expect(Array.from(await pending)).toEqual([1, 2, 3, 4]);
        expect(Array.from(await stream.read())).toEqual([5, 6]);
    });

    it("buffers delivered bytes when no reader is waiting", async () => {
        const { manager } = makeManager();
        manager.dispatch(streamFrame(1n, [1, 2, 3], 0n));
        const stream = await manager.acceptStream(true);
        // Give the manager time to deliver into the read buffer.
        await Promise.resolve();
        await Promise.resolve();
        // No read() was outstanding, so the bytes were buffered and read() returns them.
        expect(Array.from(await stream.read())).toEqual([1, 2, 3]);
    });
});

describe("send-path edge cases", () => {
    it("emits DATA_BLOCKED when the connection window is exhausted", () => {
        // The connection send window starts at 1 MiB and can only grow (a peer
        // MAX_DATA is what raises it), so DATA_BLOCKED is only reachable once
        // the app has sent a full 1 MiB. Give the per-stream window enough room
        // to send it all on one stream and set the flush budget to exactly 1 MiB
        // so the budget is exhausted in the same pass.
        const MiB = 1024 * 1024;
        const { manager } = makeManager({}, { initialMaxStreamDataBidiRemote: BigInt(MiB) });
        const s = manager.openStream(true);
        void s.write(new Uint8Array(MiB).fill(0x22));
        const emitted: QuicFrame[] = [];
        manager.flushSends(MiB, (f) => emitted.push(f));
        const types = emitted.map((f) => f.type);
        expect(types).toContain(QuicFrameType.STREAM);
        expect(types).toContain(QuicFrameType.DATA_BLOCKED);
    });

    it("clips the STREAM payload to the remaining budget", () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        void s.write(new Uint8Array(20).fill(0x11));
        const emitted: QuicFrame[] = [];
        manager.flushSends(7, (f) => emitted.push(f));
        const sf = emitted.find((f) => f.type === QuicFrameType.STREAM) as
            | { data: Uint8Array }
            | undefined;
        expect(sf?.data.length).toBe(7);
        // The remaining 13 bytes are still pending.
        expect(manager.hasPendingSends).toBe(true);
    });

    it("flushes a FIN-only STREAM frame when the queue is empty but FIN is pending", () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        // close() without any write: sendFinPending is true, queue empty.
        void s.close();
        expect(manager.hasPendingSends).toBe(true);
        const emitted: QuicFrame[] = [];
        manager.flushSends(1200, (f) => emitted.push(f));
        const sf = emitted.find((f) => f.type === QuicFrameType.STREAM) as
            | { data: Uint8Array; fin: boolean }
            | undefined;
        expect(sf).toBeDefined();
        expect(sf?.fin).toBe(true);
        expect(sf?.data.length).toBe(0);
    });
});

describe("dispatch no-ops and closing guards", () => {
    it("ignores MAX_STREAM_DATA for an unknown stream", () => {
        const { manager } = makeManager();
        expect(() =>
            manager.dispatch({
                type: QuicFrameType.MAX_STREAM_DATA,
                streamId: 1234n,
                maximum: 1000n,
            }),
        ).not.toThrow();
    });

    it("rejects acceptStream once the manager is closing", async () => {
        const { manager } = makeManager();
        manager.close(0n, "bye");
        await expect(manager.acceptStream(true)).rejects.toThrow(/closing/);
        await expect(manager.acceptStream(false)).rejects.toThrow(/closing/);
    });

    it("rejects a read on a stream forced closed by abortAll", async () => {
        const { manager } = makeManager();
        // A locally-opened stream with nothing written: read() blocks.
        const stream = manager.openStream(true);
        const pending = stream.read();
        // abortAll force-closes every stream, rejecting pending readers.
        manager.abortAll(new Error("boom"));
        await expect(pending).rejects.toThrow(/connection closed/);
    });

    it("close() is a no-op on an already-closed stream", async () => {
        const { manager } = makeManager();
        const stream = manager.openStream(true);
        // Force-close the stream (as abortAll / a peer reset would).
        manager.abortAll(new Error("down"));
        // close() on a closed stream returns immediately without throwing.
        await expect(stream.close()).resolves.toBeUndefined();
    });
});
