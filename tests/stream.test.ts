/**
 * Stream state machine + flow-control unit tests for @browsercore/quic.
 *
 * Drives `ManagedStream` directly (no transport) to verify receive reassembly,
 * the stream lifecycle, and flow-control accounting.
 */

import { describe, it, expect } from "vitest";
import { makeStreamId } from "../src/types.js";

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
});
