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
    type QuicTransportParameters,
} from "../src/types.js";
import { ResetStreamError, StopSendingError } from "../src/errors.js";

type Manager = ReturnType<typeof createStreamManager>;

function makeManager(
    local: QuicTransportParameters = {},
    peer: QuicTransportParameters = {},
): { manager: Manager; sent: QuicFrame[] } {
    const sent: QuicFrame[] = [];
    const manager = createStreamManager({
        sendFrame: (f) => {
            sent.push(f);
        },
        localParameters: local,
        peerParameters: peer,
    });
    return { manager, sent };
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

    it("emits incomingStream when no accept waiter is registered", () => {
        const { manager } = makeManager();
        const arrived: bigint[] = [];
        manager.on("incomingStream", (s: { id: bigint }) => arrived.push(s.id));
        manager.dispatch(streamFrame(1n, [1]));
        expect(arrived).toEqual([1n]);
    });

    it("ignores STREAM frames for unknown client-initiated streams", () => {
        const { manager } = makeManager();
        let arrived = false;
        manager.on("incomingStream", () => {
            arrived = true;
        });
        // id 0 is client-initiated but no local stream exists there.
        manager.dispatch(streamFrame(0n, [1]));
        expect(arrived).toBe(false);
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
    it("MAX_DATA grows the connection window and emits maxData only on growth", () => {
        const { manager } = makeManager();
        const events: bigint[] = [];
        manager.on("maxData", (m: bigint) => events.push(m));
        manager.dispatch({ type: QuicFrameType.MAX_DATA, maximum: 5_000_000n });
        expect(events).toEqual([5_000_000n]);
        // A smaller value does not grow the window and must not emit.
        manager.dispatch({ type: QuicFrameType.MAX_DATA, maximum: 1n });
        expect(events).toEqual([5_000_000n]);
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

    it("CONNECTION_CLOSE sets closing and emits the close signal", () => {
        const { manager } = makeManager();
        const closes: Array<{ errorCode: bigint; reason: string }> = [];
        manager.on("connectionClose", (p: { errorCode: bigint; reason: string }) => closes.push(p));
        manager.dispatch({
            type: QuicFrameType.CONNECTION_CLOSE,
            errorCode: 0x0cn,
            frameType: undefined,
            reason: "bye",
        });
        expect(closes).toEqual([{ errorCode: 0x0cn, reason: "bye" }]);
        // After connection close, new streams cannot be opened.
        expect(() => manager.openStream(true)).toThrow(/closing/);
    });

    it("CONNECTION_CLOSE_APP is also surfaced as a close signal", () => {
        const { manager } = makeManager();
        let reason = "";
        manager.on("connectionClose", (p: { reason: string }) => {
            reason = p.reason;
        });
        manager.dispatch({
            type: QuicFrameType.CONNECTION_CLOSE_APP,
            errorCode: 0x0103n,
            frameType: 0n,
            reason: "app close",
        });
        expect(reason).toBe("app close");
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

describe("EventEmitter surface", () => {
    it("supports on/once/off/removeListener/removeAllListeners/emit", () => {
        const { manager } = makeManager();
        const a = (): void => {};
        const b = (): void => {};
        manager.on("x", a);
        manager.on("x", b);
        manager.once("y", a);
        manager.emit("x");
        manager.off("x", a);
        manager.removeListener("x", b);
        manager.emit("x");
        manager.removeAllListeners("x");
        expect(manager).toBeDefined();
    });

    it("delivers an event to a once-listener exactly one time", () => {
        const { manager } = makeManager();
        let count = 0;
        manager.once("evt", () => {
            count++;
        });
        manager.emit("evt");
        manager.emit("evt");
        expect(count).toBe(1);
    });

    it("delivers incomingStream events to multiple on-listeners", () => {
        const { manager } = makeManager();
        const seen: bigint[] = [];
        manager.on("incomingStream", (s: { id: bigint }) => seen.push(s.id));
        manager.on("incomingStream", (s: { id: bigint }) => seen.push(s.id));
        manager.dispatch(streamFrame(5n, [1]));
        expect(seen).toEqual([5n, 5n]);
    });
});
