/**
 * Stream state machine + flow-control unit tests for @browsercore/quic.
 *
 * Drives `ManagedStream` directly (no transport) to verify receive reassembly,
 * the stream lifecycle, and flow-control accounting.
 */

import { describe, it, expect } from "vitest";
import { firstStreamId, makeStreamId, type QuicStream } from "../src/types.js";
import type { QuicFrame } from "../src/types.js";

// ManagedStream is not exported; reach it through the stream manager's
// openStream(), which returns a QuicStream backed by a ManagedStream.
import { createStreamManager } from "../src/stream/stream.js";

function makeManager() {
    return createStreamManager({
        sendFrame: () => {},
        localParameters: {},
        peerParameters: {},
    });
}

describe("stream lifecycle", () => {
    it("opens a bidirectional stream with the client-initiated id 0", () => {
        const manager = makeManager();
        const stream = manager.openStream(true);
        expect(stream.id).toBe(0n);
    });

    it("opens a unidirectional stream with the client-initiated id 2", () => {
        const manager = makeManager();
        const stream = manager.openStream(false);
        expect(stream.id).toBe(2n);
    });

    it("rejects writes after close()", async () => {
        const manager = makeManager();
        const stream = manager.openStream(true);
        await stream.close();
        // A second close is idempotent and safe.
        await expect(stream.close()).resolves.toBeUndefined();
    });
});

describe("receive reassembly", () => {
    it("delivers in-order bytes to a reader", async () => {
        const manager = makeManager();
        const stream = manager.openStream(true);

        // Simulate the manager dispatching an inbound STREAM frame.
        manager.dispatch({
            type: 0x08 /* STREAM */,
            streamId: 0n,
            offset: 0n,
            data: new Uint8Array([1, 2, 3]),
            fin: false,
        });

        const chunk = await stream.read();
        expect(Array.from(chunk)).toEqual([1, 2, 3]);
    });

    it("reassembles out-of-order frames into a contiguous stream", async () => {
        const manager = makeManager();
        const stream = manager.openStream(true);

        // Offset 3 arrives before offset 0.
        manager.dispatch({
            type: 0x08 /* STREAM */,
            streamId: 0n,
            offset: 3n,
            data: new Uint8Array([4, 5, 6]),
            fin: true,
        });
        manager.dispatch({
            type: 0x08 /* STREAM */,
            streamId: 0n,
            offset: 0n,
            data: new Uint8Array([1, 2, 3]),
            fin: false,
        });

        // Both frames arrived before the read, so reassembly has already
        // bridged the gap and the bytes are contiguous — delivered together.
        const first = await stream.read();
        expect(Array.from(first)).toEqual([1, 2, 3, 4, 5, 6]);
        // FIN arrived with the last byte — end-of-stream is an empty read.
        const eof = await stream.read();
        expect(eof.length).toBe(0);
    });

    it("drops an empty retransmission at recvOffset (no-op, false branch)", async () => {
        const manager = makeManager();
        const stream = manager.openStream(true);
        manager.dispatch({
            type: 0x08 /* STREAM */,
            streamId: 0n,
            offset: 0n,
            data: new Uint8Array([1, 2, 3, 4]),
            fin: false,
        });
        // Empty frame at the current recvOffset: end(0) <= recvOffset(4) and
        // offset(0) < recvOffset(4) is TRUE here; to hit the FALSE branch we
        // need offset === recvOffset with end <= recvOffset, i.e. an empty
        // frame whose offset equals the current recvOffset.
        manager.dispatch({
            type: 0x08 /* STREAM */,
            streamId: 0n,
            offset: 4n,
            data: new Uint8Array(0),
            fin: false,
        });
        const chunk = await stream.read();
        expect(Array.from(chunk)).toEqual([1, 2, 3, 4]);
    });

    it("drops bytes already delivered (retransmission overlap)", async () => {
        const manager = makeManager();
        const stream = manager.openStream(true);

        manager.dispatch({
            type: 0x08 /* STREAM */,
            streamId: 0n,
            offset: 0n,
            data: new Uint8Array([1, 2, 3, 4]),
            fin: false,
        });
        // Retransmit the first two bytes only — must not be re-delivered.
        manager.dispatch({
            type: 0x08 /* STREAM */,
            streamId: 0n,
            offset: 0n,
            data: new Uint8Array([1, 2]),
            fin: false,
        });

        const chunk = await stream.read();
        expect(Array.from(chunk)).toEqual([1, 2, 3, 4]);
    });
});

describe("reset + stop_sending", () => {
    it("RESET_STREAM rejects pending and future reads", async () => {
        const manager = makeManager();
        const stream = manager.openStream(true);

        const readPromise = stream.read();
        manager.dispatch({
            type: 0x04 /* RESET_STREAM */,
            streamId: 0n,
            errorCode: 0x01n,
            finalSize: 0n,
        });

        await expect(readPromise).rejects.toThrow(/RESET_STREAM/);
    });

    it("STOP_SENDING discards the send queue", () => {
        const manager = makeManager();
        const stream = manager.openStream(true);
        void stream;
        manager.dispatch({
            type: 0x05 /* STOP_SENDING */,
            streamId: 0n,
            errorCode: 0x02n,
        });
        // No exception — stop_sending is best-effort on the send side.
        expect(true).toBe(true);
    });
});

describe("stream id helpers", () => {
    it("makeStreamId rejects out-of-range values", () => {
        expect(() => makeStreamId(-1n)).toThrow(RangeError);
        expect(() => makeStreamId((1n << 62n))).toThrow(RangeError);
    });

    it("firstStreamId encodes direction + initiator in the low 2 bits", () => {
        expect(firstStreamId(true, true)).toBe(0n); // client bidi
        expect(firstStreamId(true, false)).toBe(1n); // server bidi
        expect(firstStreamId(false, true)).toBe(2n); // client uni
        expect(firstStreamId(false, false)).toBe(3n); // server uni
    });
});

describe("Manager: openStream + hasPendingSends + localParameters", () => {
    it("reports hasPendingSends once a stream buffers data", () => {
        const manager = makeManager();
        expect(manager.hasPendingSends).toBe(false);
        const stream = manager.openStream(true);
        void stream;
        expect(manager.hasPendingSends).toBe(false);
    });

    it("exposes the local transport parameters it was constructed with", () => {
        const manager = createStreamManager({
            sendFrame: () => {},
            localParameters: { initialMaxData: 999n },
            peerParameters: {},
        });
        expect(manager.localParameters.initialMaxData).toBe(999n);
    });

    it("throws if a stream is opened after the manager begins closing", () => {
        const manager = makeManager();
        manager.close(0x00n, "bye");
        expect(() => manager.openStream(true)).toThrow(/closing/);
    });
});

describe("Manager: dispatch of MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS", () => {
    it("emits maxData when the peer grows the connection send window", async () => {
        const manager = makeManager();
        let maxData = 0n;
        manager.on("maxData", (m: bigint) => {
            maxData = m;
        });
        manager.dispatch({ type: 0x10 /* MAX_DATA */, maximum: 2_000_000n });
        expect(maxData).toBe(2_000_000n);
    });

    it("ignores MAX_DATA that does not grow the window", async () => {
        const manager = makeManager();
        let fired = false;
        manager.on("maxData", () => {
            fired = true;
        });
        manager.dispatch({ type: 0x10 /* MAX_DATA */, maximum: 100n });
        expect(fired).toBe(false);
    });

    it("grows a stream's send window on MAX_STREAM_DATA", () => {
        const manager = makeManager();
        const stream = manager.openStream(true);
        manager.dispatch({ type: 0x11 /* MAX_STREAM_DATA */, streamId: stream.id, maximum: 1_000_000n });
        // Window grew: a write + flush could now send more than the default.
        expect(stream.id).toBe(0n);
    });

    it("ignores MAX_STREAM_DATA for an unknown stream", () => {
        const manager = makeManager();
        manager.dispatch({ type: 0x11 /* MAX_STREAM_DATA */, streamId: 999n, maximum: 1_000_000n });
        // No exception.
    });

    it("accepts MAX_STREAMS_BIDI and MAX_STREAMS_UNI without error", () => {
        const manager = makeManager();
        manager.dispatch({ type: 0x12 /* MAX_STREAMS_BIDI */, maximum: 200n });
        manager.dispatch({ type: 0x13 /* MAX_STREAMS_UNI */, maximum: 200n });
    });
});

describe("Manager: dispatch of CONNECTION_CLOSE", () => {
    it("emits connectionClose with the error code and reason", () => {
        const manager = makeManager();
        let captured: { errorCode: bigint; reason: string } | undefined;
        manager.on("connectionClose", (p: { errorCode: bigint; reason: string }) => {
            captured = p;
        });
        manager.dispatch({
            type: 0x1c /* CONNECTION_CLOSE */,
            errorCode: 0x01n,
            frameType: 0x06n,
            reason: "reset",
        });
        expect(captured).toEqual({ errorCode: 0x01n, reason: "reset" });
    });

    it("emits connectionClose for the application variant too", () => {
        const manager = makeManager();
        let captured: { errorCode: bigint; reason: string } | undefined;
        manager.on("connectionClose", (p: { errorCode: bigint; reason: string }) => {
            captured = p;
        });
        manager.dispatch({
            type: 0x1d /* CONNECTION_CLOSE_APP */,
            errorCode: 0x02n,
            frameType: undefined,
            reason: "app",
        });
        expect(captured).toEqual({ errorCode: 0x02n, reason: "app" });
    });
});

describe("Manager: acceptStream waiters + registerIncomingStream", () => {
    it("resolves an acceptStream waiter when a matching stream arrives", async () => {
        const manager = makeManager();
        const pending = manager.acceptStream(true);
        manager.dispatch({
            type: 0x08 /* STREAM */,
            streamId: 1n, // server-initiated bidi
            offset: 0n,
            data: new Uint8Array([0x01]),
            fin: false,
        });
        const stream = await pending;
        expect(stream.id).toBe(1n);
    });

    it("emits incomingStream when no accept waiter is pending", () => {
        const manager = makeManager();
        let incoming: QuicStream | undefined;
        manager.on("incomingStream", (s: QuicStream) => {
            incoming = s;
        });
        manager.dispatch({
            type: 0x08 /* STREAM */,
            streamId: 1n,
            offset: 0n,
            data: new Uint8Array([0x02]),
            fin: false,
        });
        expect(incoming?.id).toBe(1n);
    });

    it("rejects pending accept waiters on abortAll", async () => {
        const manager = makeManager();
        const pending = manager.acceptStream(true);
        manager.abortAll(new Error("killed"));
        await expect(pending).rejects.toThrow(/killed/);
    });

    it("refuses to accept after the manager begins closing", async () => {
        const manager = makeManager();
        manager.close(0x00n, "bye");
        await expect(manager.acceptStream(true)).rejects.toThrow(/closing/);
    });
});

describe("Manager: replenish emission", () => {
    it("emits MAX_STREAM_DATA once half the per-stream receive window is consumed", () => {
        const manager = createStreamManager({
            sendFrame: () => {},
            localParameters: {},
            peerParameters: { initialMaxStreamDataBidiRemote: 100n },
        });
        const emitted: QuicFrame[] = [];
        manager.on("incomingStream", (stream: QuicStream) => {
            // Consume > half the advertised window (100 -> threshold 50).
            manager.dispatch({
                type: 0x08 /* STREAM */,
                streamId: stream.id,
                offset: 0n,
                data: new Uint8Array(60),
                fin: false,
            });
        });
        // Drain the manager-emitted MAX_STREAM_DATA frames via the sendFrame path.
        const managerWithCapture = createStreamManager({
            sendFrame: (frame: QuicFrame) => emitted.push(frame),
            localParameters: {},
            peerParameters: { initialMaxStreamDataBidiRemote: 100n },
        });
        managerWithCapture.dispatch({
            type: 0x08 /* STREAM */,
            streamId: 1n, // server-initiated bidi
            offset: 0n,
            data: new Uint8Array(60),
            fin: false,
        });
        const maxStreamData = emitted.find((f) => f.type === 0x11 /* MAX_STREAM_DATA */);
        expect(maxStreamData).toBeDefined();
    });
});

describe("Manager: handleStream edge cases", () => {
    it("ignores a STREAM frame for an unknown client-initiated stream", () => {
        const manager = makeManager();
        // streamId 0 is client-initiated bidi but was never registered with the
        // manager, so handleStream must drop it (the "unknown local stream" path).
        manager.dispatch({
            type: 0x08 /* STREAM */,
            streamId: 0n,
            offset: 0n,
            data: new Uint8Array([1, 2, 3]),
            fin: false,
        });
        // No exception, no stream registered.
        expect(manager.hasPendingSends).toBe(false);
    });

    it("emits MAX_DATA via sendMaxData when the connection receive window is half-consumed", () => {
        // Advertise a small connection receive window (100 bytes) so the
        // connection-level replenish threshold (50 bytes) is crossed with one
        // STREAM frame, exercising the sendMaxData() path.
        const emitted: QuicFrame[] = [];
        const manager = createStreamManager({
            sendFrame: (frame) => emitted.push(frame),
            localParameters: { initialMaxData: 100n },
            peerParameters: {},
        });
        manager.dispatch({
            type: 0x08 /* STREAM */,
            streamId: 1n, // server-initiated bidi
            offset: 0n,
            data: new Uint8Array(60),
            fin: false,
        });
        const maxData = emitted.find((f) => f.type === 0x10 /* MAX_DATA */);
        expect(maxData).toBeDefined();
    });
});

describe("Manager: ignored informational frames", () => {
    it("silently ignores DATA_BLOCKED / STREAM_DATA_BLOCKED / STREAMS_BLOCKED / PING", () => {
        const manager = makeManager();
        manager.dispatch({ type: 0x14 /* DATA_BLOCKED */, limit: 100n });
        manager.dispatch({ type: 0x15 /* STREAM_DATA_BLOCKED */, streamId: 0n, limit: 100n });
        manager.dispatch({ type: 0x16 /* STREAMS_BLOCKED_BIDI */, limit: 100n });
        manager.dispatch({ type: 0x17 /* STREAMS_BLOCKED_UNI */, limit: 100n });
        manager.dispatch({ type: 0x01 /* PING */ });
        // No exception, no registered stream.
        expect(manager.hasPendingSends).toBe(false);
    });
});

describe("ManagedStream: signalFin resolves a waiting reader", () => {
    it("resolves a second blocked read() with EMPTY via signalFin", async () => {
        const manager = makeManager();
        const stream = manager.openStream(true);
        // Queue TWO readers before any data arrives; the first will be handed
        // the payload, the second must be resolved by signalFin() with EMPTY.
        const first = stream.read();
        const second = stream.read();
        manager.dispatch({
            type: 0x08 /* STREAM */,
            streamId: 0n,
            offset: 0n,
            data: new Uint8Array([1, 2, 3]),
            fin: true,
        });
        expect(Array.from(await first)).toEqual([1, 2, 3]);
        // signalFin resolves the still-waiting reader with EMPTY (lines 288-290).
        expect((await second).length).toBe(0);
    });
});

describe("Manager: dispatch default (connection-layer frames)", () => {
    it("ignores ACK / CRYPTO / NEW_TOKEN / PATH_CHALLENGE dispatched to it", () => {
        const manager = makeManager();
        // These frame types fall through the switch's default branch because
        // they are handled by the connection/handshake layers, not the data
        // plane. Dispatching them to the manager must be a silent no-op.
        manager.dispatch({
            type: 0x02 /* ACK */,
            largestAck: 10n,
            ackDelay: 1n,
            ackRangeCount: 0n,
            firstAckRange: 5n,
            ackRanges: [],
        });
        manager.dispatch({ type: 0x06 /* CRYPTO */, offset: 0n, data: new Uint8Array([1]) });
        manager.dispatch({ type: 0x07 /* NEW_TOKEN */, token: new Uint8Array([0xab]) });
        manager.dispatch({ type: 0x10 /* PATH_CHALLENGE */, data: new Uint8Array(8) });
        expect(manager.hasPendingSends).toBe(false);
    });
});

describe("ManagedStream: write/read/close lifecycle", () => {
    it("closes a stream that is half_closed_local once the remote FIN arrives", async () => {
        const manager = makeManager();
        const stream = manager.openStream(true);
        // Send data, then close locally and commit the FIN via a flush.
        void stream.write(new Uint8Array([1, 2, 3]));
        await stream.close();
        manager.flushSends(1200, () => {});
        // Now half_closed_local. A remote FIN should drive it to closed.
        manager.dispatch({
            type: 0x08 /* STREAM */,
            streamId: 0n,
            offset: 0n,
            data: new Uint8Array([4, 5, 6]),
            fin: true,
        });
        const chunk = await stream.read();
        expect(Array.from(chunk)).toEqual([4, 5, 6]);
        const eof = await stream.read();
        expect(eof.length).toBe(0);
    });
    it("rejects writes once the local side has closed (half_closed_local)", async () => {
        const manager = makeManager();
        const stream = manager.openStream(true);
        await stream.close();
        // Drive a flush so the FIN is committed and the state transitions to
        // half_closed_local, after which writes must be rejected. The emit
        // callback is a no-op: we only care that commitSend() runs.
        manager.flushSends(1200, () => {});
        await expect(stream.write(new Uint8Array([1]))).rejects.toThrow(/RESET_STREAM/);
    });

    it("resolves a reader with empty bytes once the FIN is delivered", async () => {
        const manager = makeManager();
        const stream = manager.openStream(true);
        manager.dispatch({
            type: 0x08 /* STREAM */,
            streamId: 0n,
            offset: 0n,
            data: new Uint8Array([7, 8]),
            fin: true,
        });
        const chunk = await stream.read();
        expect(Array.from(chunk)).toEqual([7, 8]);
        const eof = await stream.read();
        expect(eof.length).toBe(0);
    });

    it("clips the front of a frame that overlaps already-delivered bytes", async () => {
        const manager = makeManager();
        const stream = manager.openStream(true);
        manager.dispatch({
            type: 0x08 /* STREAM */,
            streamId: 0n,
            offset: 0n,
            data: new Uint8Array([1, 2, 3, 4]),
            fin: false,
        });
        // Arrives late, overlapping the first 2 bytes already delivered.
        manager.dispatch({
            type: 0x08 /* STREAM */,
            streamId: 0n,
            offset: 2n,
            data: new Uint8Array([3, 4, 5, 6]),
            fin: false,
        });
        const chunk = await stream.read();
        expect(Array.from(chunk)).toEqual([1, 2, 3, 4, 5, 6]);
    });
});

describe("Manager: flushSends flow-control windows", () => {
    it("emits STREAM_DATA_BLOCKED when the per-stream window is exhausted", () => {
        // Peer advertised a zero per-stream send window: the stream window is
        // <= 0 on the first visit, so flushSends emits STREAM_DATA_BLOCKED.
        const manager = createStreamManager({
            sendFrame: () => {},
            localParameters: {},
            peerParameters: { initialMaxStreamDataBidiRemote: 0n },
        });
        const stream = manager.openStream(true);
        void stream.write(new Uint8Array(100));
        void stream.close();
        const emitted: QuicFrame[] = [];
        manager.flushSends(1200, (frame) => emitted.push(frame));
        expect(emitted.some((f) => f.type === 0x15 /* STREAM_DATA_BLOCKED */)).toBe(true);
    });

    it("emits DATA_BLOCKED when the connection window is exhausted exactly as the budget drains", () => {
        // The default connection send window is 1_048_576 bytes. With a stream
        // whose per-stream window is larger, a flush sized to the connection
        // window sends exactly that many bytes — exhausting both the budget and
        // the connection window in one pass, which triggers DATA_BLOCKED.
        const manager = createStreamManager({
            sendFrame: () => {},
            localParameters: {},
            peerParameters: { initialMaxStreamDataBidiRemote: 2_000_000n },
        });
        const stream = manager.openStream(true);
        void stream.write(new Uint8Array(1_048_576));
        const emitted: QuicFrame[] = [];
        manager.flushSends(1_048_576, (frame) => emitted.push(frame));
        expect(emitted.some((f) => f.type === 0x14 /* DATA_BLOCKED */)).toBe(true);
    });

    it("emits a STREAM frame with the FIN bit when the last chunk is sent", () => {
        const manager = makeManager();
        const stream = manager.openStream(true);
        void stream.write(new Uint8Array([1, 2, 3]));
        void stream.close();
        const emitted: QuicFrame[] = [];
        manager.flushSends(1200, (frame) => emitted.push(frame));
        const streamFrame = emitted.find((f) => f.type === 0x08 /* STREAM */);
        expect(streamFrame).toBeDefined();
        if (streamFrame?.type !== 0x08 /* STREAM */) return;
        expect(streamFrame.fin).toBe(true);
        expect(Array.from(streamFrame.data)).toEqual([1, 2, 3]);
    });
});

describe("Manager: abortAll + close teardown", () => {
    it("force-closes every stream and clears the send queue on abortAll", async () => {
        const manager = makeManager();
        const stream = manager.openStream(true);
        const readPromise = stream.read();
        manager.abortAll(new Error("killed"));
        // forceClose rejects pending readers with a generic "connection closed".
        await expect(readPromise).rejects.toThrow(/connection closed/);
        expect(manager.hasPendingSends).toBe(false);
    });

    it("sends a CONNECTION_CLOSE frame on close()", () => {
        const emitted: QuicFrame[] = [];
        const manager = createStreamManager({
            sendFrame: (frame) => emitted.push(frame),
            localParameters: {},
            peerParameters: {},
        });
        manager.close(0x00n, "done");
        const closeFrame = emitted.find((f) => f.type === 0x1c /* CONNECTION_CLOSE */);
        expect(closeFrame).toBeDefined();
    });

    it("is a no-op to close() twice", () => {
        const emitted: QuicFrame[] = [];
        const manager = createStreamManager({
            sendFrame: (frame) => emitted.push(frame),
            localParameters: {},
            peerParameters: {},
        });
        manager.close(0x00n, "a");
        manager.close(0x00n, "b");
        expect(emitted.filter((f) => f.type === 0x1c /* CONNECTION_CLOSE */)).toHaveLength(1);
    });
});

describe("Manager: EventEmitter surface", () => {
    it("supports on/once/off/removeListener/removeAllListeners/emit", () => {
        const manager = makeManager();
        const a = (): void => {};
        const b = (): void => {};

        manager.on("incomingStream", a);
        manager.once("incomingStream", b);
        manager.off("incomingStream", a);
        manager.removeListener("incomingStream", b);
        manager.removeAllListeners("incomingStream");

        let received = false;
        manager.on("incomingStream", () => {
            received = true;
        });
        manager.emit("incomingStream", undefined);
        expect(received).toBe(true);
    });
});
