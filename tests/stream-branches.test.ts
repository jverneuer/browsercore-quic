/**
 * Targeted branch coverage for src/stream/stream.ts.
 *
 * The existing stream-manager.test.ts exercises the public happy paths. This
 * file aims at the remaining uncovered branches: flow-control window
 * exhaustion sub-branches (allow <= 0 with a live stream window, budget-exhausted
 * loop break, mid-loop connection-window exhaustion), send-side waiter
 * resolution/rejection (drainSendWaiters / rejectWriters bodies), the
 * signalFin early-return, the drainReassembly gap break, the updatePeerParameters
 * setter, and the assertNever default in dispatch.
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

describe("flow-control window exhaustion sub-branches", () => {
    it("skips a stream (no STREAM_DATA_BLOCKED) when only the connection window is exhausted", () => {
        const MiB = 1024 * 1024;
        // Per-stream window large enough (1 MiB); connection window defaults to 1 MiB.
        const { manager } = makeManager({}, { initialMaxStreamDataBidiRemote: BigInt(MiB) });
        const s0 = manager.openStream(true);
        void s0.write(new Uint8Array(MiB).fill(0x11));
        // Pass 1: send the full 1 MiB so the connection window is exhausted.
        manager.flushSends(MiB + 1200, () => {});

        // A fresh stream with data to send but no connection credit left.
        const s1 = manager.openStream(true);
        void s1.write(new Uint8Array([1, 2, 3]));
        const emitted: QuicFrame[] = [];
        manager.flushSends(1200, (f) => emitted.push(f));

        // allow = min(streamWindow>0, connWindow=0, budget) = 0 → continue. No STREAM,
        // no STREAM_DATA_BLOCKED. The flush budget is untouched (>0) so no DATA_BLOCKED.
        expect(emitted).toHaveLength(0);
        expect(manager.hasPendingSends).toBe(true);
        void s0;
        void s1;
    });

    it("breaks the flush loop once the payload budget is exhausted (line 575)", () => {
        const { manager } = makeManager();
        const s0 = manager.openStream(true);
        const s1 = manager.openStream(true);
        void s0.write(new Uint8Array(20).fill(0x11));
        void s1.write(new Uint8Array(20).fill(0x22));

        const emitted: QuicFrame[] = [];
        manager.flushSends(7, (f) => emitted.push(f));

        // s0 consumes the whole 7-byte budget; the loop breaks before s1 is reached.
        const sfs = emitted.filter((f) => f.type === QuicFrameType.STREAM);
        expect(sfs).toHaveLength(1);
        expect((sfs[0] as { streamId: bigint }).streamId).toBe(0n);
        expect((sfs[0] as { data: Uint8Array }).data.length).toBe(7);
        // s1 still has pending bytes.
        expect(manager.hasPendingSends).toBe(true);
    });
});

describe("send-side waiter resolution / rejection (drainSendWaiters / rejectWriters)", () => {
    it("drainSendWaiters resolves an injected waiter once the queue drains (lines 335-341)", () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        void s.write(new Uint8Array([1, 2, 3]));
        let resolved = false;
        (s as unknown as { sendWaiters: Array<{ resolve: () => void; reject: (e: Error) => void }> }).
            sendWaiters.push({ resolve: () => { resolved = true; }, reject: () => {} });

        // Draining the send queue commits the send → commitSend → drainSendWaiters.
        manager.flushSends(1200, () => {});
        expect(resolved).toBe(true);
    });

    it("RESET_STREAM rejects injected send waiters via rejectWriters (lines 357-359)", () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        const rejected: Error[] = [];
        (s as unknown as { sendWaiters: Array<{ resolve: () => void; reject: (e: Error) => void }> }).
            sendWaiters.push({ resolve: () => {}, reject: (e: Error) => rejected.push(e) });

        manager.dispatch({
            type: QuicFrameType.RESET_STREAM,
            streamId: 0n,
            errorCode: 0x07n,
            finalSize: 5n,
        });

        expect(rejected).toHaveLength(1);
        expect(rejected[0]).toBeInstanceOf(ResetStreamError);
    });

    it("STOP_SENDING rejects injected send waiters via rejectWriters (lines 357-359)", () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        void s.write(new Uint8Array([1, 2, 3]));
        const rejected: Error[] = [];
        (s as unknown as { sendWaiters: Array<{ resolve: () => void; reject: (e: Error) => void }> }).
            sendWaiters.push({ resolve: () => {}, reject: (e: Error) => rejected.push(e) });

        manager.dispatch({
            type: QuicFrameType.STOP_SENDING,
            streamId: 0n,
            errorCode: 0x01n,
        });

        expect(rejected).toHaveLength(1);
        expect(rejected[0]).toBeInstanceOf(StopSendingError);
        // The send queue is cleared so nothing remains pending.
        expect(manager.hasPendingSends).toBe(false);
    });
});

describe("receive-side reassembly branches", () => {
    it("drainReassembly breaks at a gap (line 278)", async () => {
        const { manager } = makeManager();
        manager.dispatch(streamFrame(1n, [5, 6], 4n));   // buffered, gap at 0..3
        manager.dispatch(streamFrame(1n, [9], 8n));       // another gap
        const stream = await manager.acceptStream(true);

        const readP = stream.read();
        // Not yet contiguous (recvOffset=0) → read() blocks.
        await expect(Promise.race([readP, Promise.resolve("pending")])).resolves.toBe("pending");

        // Bridge only the first gap: delivers [1,2,3,4] + drains [5,6]@4, stops at [9]@8.
        manager.dispatch(streamFrame(1n, [1, 2, 3, 4], 0n));
        expect(Array.from(await readP)).toEqual([1, 2, 3, 4]);
        // [5,6] was pulled into the read buffer by drainReassembly.
        expect(Array.from(await stream.read())).toEqual([5, 6]);
        // [9]@8 is past the gap at 7 → the next read() blocks again.
        const readP2 = stream.read();
        await expect(Promise.race([readP2, Promise.resolve("pending")])).resolves.toBe("pending");
    });

    it("signalFin early-returns when the FIN was already delivered (lines 297-299)", async () => {
        const { manager } = makeManager();
        const pending = manager.acceptStream(true);
        await Promise.resolve();
        // Empty FIN at offset 2, then the bytes that bridge to it.
        manager.dispatch(streamFrame(1n, [], 2n, true));
        manager.dispatch(streamFrame(1n, [1, 2], 0n));
        const stream = await pending;

        expect(Array.from(await stream.read())).toEqual([1, 2]);
        // Retransmit [1,2,3]: clips to [3], extends recvOffset past recvFinOffset (2)
        // → signalFin called again, but finDelivered is already true → early return.
        manager.dispatch(streamFrame(1n, [1, 2, 3], 0n));
        expect(Array.from(await stream.read())).toEqual([3]);
        // EOF already delivered: subsequent read resolves to an empty chunk.
        expect((await stream.read()).length).toBe(0);
    });
});

describe("peer control frames (deep paths)", () => {
    it("STOP_SENDING clears a pending FIN so no FIN-only frame flushes", () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        void s.write(new Uint8Array([1, 2]));
        void s.close(); // sendFinPending = true
        manager.dispatch({
            type: QuicFrameType.STOP_SENDING,
            streamId: 0n,
            errorCode: 0x01n,
        });
        // Both the queue and the pending FIN are cleared.
        expect(manager.hasPendingSends).toBe(false);
        const emitted: QuicFrame[] = [];
        manager.flushSends(1200, (f) => emitted.push(f));
        expect(emitted).toHaveLength(0);
    });
});

describe("manager-level branches", () => {
    it("updatePeerParameters updates the parameters used for subsequently opened streams (line 799)", () => {
        const { manager } = makeManager();
        // Shrink the per-stream send window to zero for future streams.
        manager.updatePeerParameters({ initialMaxStreamDataBidiRemote: 0n });
        const s = manager.openStream(true);
        void s.write(new Uint8Array([1]));
        const emitted: QuicFrame[] = [];
        manager.flushSends(1200, (f) => emitted.push(f));
        // Window is 0 → nothing flushes and STREAM_DATA_BLOCKED is emitted.
        expect(emitted.some((f) => f.type === QuicFrameType.STREAM_DATA_BLOCKED)).toBe(true);
        expect(emitted.some((f) => f.type === QuicFrameType.STREAM)).toBe(false);
    });

    it("throws via assertNever on an unhandled frame type (line 673)", () => {
        const { manager } = makeManager();
        expect(() => manager.dispatch({ type: 0xff } as QuicFrame)).toThrow(/Unexpected value/);
    });
});
