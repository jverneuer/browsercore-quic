/**
 * Targeted coverage tests for the remaining uncovered branches in
 * src/stream/stream.ts.
 *
 * stream-manager.test.ts exercises the public surface; this file aims at the
 * internal lines v8 still reports as uncovered:
 *   - drainSendWaiters resolving a waiting writer (lines 338-340)
 *   - rejectWriters rejecting a waiting writer (lines 357-359)
 *   - the budget-exhaustion break in flushSends (line 575)
 *   - the defensive payload clip after peekSend (line 596)
 *
 * The sendWaiters array is private and is never populated through the public
 * write() API (write() resolves immediately), so the resolve/reject paths are
 * exercised by injecting a waiter via an `as any` cast. Line 596 is dead code
 * given peekSend's clipping contract; it is exercised by overriding peekSend
 * on the instance to return more than the allowed budget.
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
        signals: {
            onIncomingStream: () => {},
            onConnectionClose: () => {},
            onMaxData: () => {},
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

describe("drainSendWaiters resolves waiting writers (lines 338-340)", () => {
    it("resolves a send waiter once the send queue drains", () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        const internal = s as unknown as {
            sendWaiters: Array<{
                resolve: () => void;
                reject: (e: Error) => void;
            }>;
        };

        // Inject a writer waiting for flow-control window to open.
        let resolved = false;
        internal.sendWaiters.push({
            resolve: () => {
                resolved = true;
            },
            reject: () => {},
        });

        // write() buffers bytes; flushSends commits them and drains the queue,
        // which triggers drainSendWaiters() and resolves the waiter.
        void s.write(new Uint8Array([1, 2, 3]));
        manager.flushSends(1200, () => {});

        expect(resolved).toBe(true);
        expect(internal.sendWaiters.length).toBe(0);
    });
});

describe("rejectWriters rejects waiting writers (lines 357-359)", () => {
    it("rejects a send waiter when the peer resets the stream", () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        const internal = s as unknown as {
            sendWaiters: Array<{
                resolve: () => void;
                reject: (e: Error) => void;
            }>;
        };

        let rejected: Error | undefined;
        internal.sendWaiters.push({
            resolve: () => {},
            reject: (e: Error) => {
                rejected = e;
            },
        });

        // Peer reset -> resetPeer -> rejectWriters.
        manager.dispatch({
            type: QuicFrameType.RESET_STREAM,
            streamId: 0n,
            errorCode: 0x01n,
            finalSize: 0n,
        });

        expect(rejected).toBeInstanceOf(ResetStreamError);
        expect(internal.sendWaiters.length).toBe(0);
    });

    it("rejects a send waiter when the peer sends STOP_SENDING", () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        const internal = s as unknown as {
            sendWaiters: Array<{
                resolve: () => void;
                reject: (e: Error) => void;
            }>;
        };

        let rejected: Error | undefined;
        internal.sendWaiters.push({
            resolve: () => {},
            reject: (e: Error) => {
                rejected = e;
            },
        });

        // Peer STOP_SENDING -> stopSending -> rejectWriters.
        manager.dispatch({
            type: QuicFrameType.STOP_SENDING,
            streamId: 0n,
            errorCode: 0x02n,
        });

        expect(rejected).toBeInstanceOf(StopSendingError);
        expect(internal.sendWaiters.length).toBe(0);
    });
});

describe("flushSends budget-exhaustion break (line 575)", () => {
    it("stops iterating streams once the flush budget is spent", () => {
        const { manager } = makeManager();
        const s1 = manager.openStream(true);
        const s2 = manager.openStream(true);
        void s1.write(new Uint8Array(10).fill(0x11));
        void s2.write(new Uint8Array(10).fill(0x22));

        // Budget of 5: stream 0 consumes it all on the first iteration, so the
        // loop hits the budget <= 0 break (line 575) before reaching stream 4.
        const emitted: QuicFrame[] = [];
        manager.flushSends(5, (f) => emitted.push(f));

        const streamFrames = emitted.filter((f) => f.type === QuicFrameType.STREAM);
        expect(streamFrames).toHaveLength(1);
        expect(streamFrames[0]).toMatchObject({ streamId: 0n });
        // Stream 4 still has its bytes pending.
        expect(manager.hasPendingSends).toBe(true);
    });
});

describe("defensive payload clip after peekSend (line 596)", () => {
    it("clips the payload when peekSend returns more than allow", () => {
        const { manager } = makeManager();
        const s = manager.openStream(true);
        const internal = s as unknown as {
            peekSend(maxBytes: number): Uint8Array;
        };

        // peekSend normally clips to maxBytes. Override it to return more than
        // allow so the defensive subarray branch on line 596 is exercised.
        internal.peekSend = (maxBytes: number) =>
            new Uint8Array(maxBytes + 5).fill(0x33);

        void s.write(new Uint8Array(20).fill(0x44));

        const emitted: QuicFrame[] = [];
        manager.flushSends(8, (f) => emitted.push(f));

        const sf = emitted.find((f) => f.type === QuicFrameType.STREAM) as
            | { streamId: bigint; data: Uint8Array }
            | undefined;
        expect(sf).toBeDefined();
        expect(sf?.streamId).toBe(0n);
        // Payload is clipped to allow (8), not the inflated peekSend length (13).
        expect(sf?.data.length).toBe(8);
    });
});

describe("reassembly branches (lines 221, 297, 302)", () => {
    it("takes the offset === recvOffset path on a below-recvOffset frame (line 221)", async () => {
        const { manager } = makeManager();
        // Deliver [1,2,3,4] at offset 0 -> recvOffset advances to 4.
        manager.dispatch(streamFrame(1n, [1, 2, 3, 4], 0n));
        const stream = await manager.acceptStream(true);
        await stream.read(); // drain the 4 bytes

        // Now dispatch an empty frame whose offset === recvOffset (4). The
        // frame's end (4) <= recvOffset (4) and offset (4) is NOT <
        // recvOffset, so the false branch of `offset < recvOffset` runs.
        manager.dispatch({
            type: QuicFrameType.STREAM,
            streamId: 1n,
            offset: 4n,
            data: new Uint8Array(0),
            fin: false,
        });

        // No new data delivered; a read() blocks.
        const pending = stream.read();
        await expect(
            Promise.race([pending, Promise.resolve("pending")]),
        ).resolves.toBe("pending");
    });

    it("resolves a waiting reader directly when data arrives (line 297)", async () => {
        const { manager } = makeManager();
        // Prime a peer-initiated stream so dispatch has a target.
        manager.dispatch(streamFrame(1n, [1]));
        const stream = await manager.acceptStream(true);
        await stream.read(); // drain the buffered byte so the next read blocks

        // read() now registers a waiter on readWaiters.
        const pending = stream.read();
        await Promise.resolve(); // let the waiter register

        // Dispatch more data: with a waiter present, deliver() resolves it
        // directly (line 297) instead of buffering.
        manager.dispatch(streamFrame(1n, [2, 3], 1n));
        expect(Array.from(await pending)).toEqual([2, 3]);
    });

    it("signalFin early-returns when finDelivered is already set (line 302)", async () => {
        const { manager } = makeManager();
        // [1] at offset 0 with FIN: contiguous deliver advances recvOffset to 1,
        // then signalFin is called and sets finDelivered = true.
        manager.dispatch(streamFrame(1n, [1], 0n, true));
        const stream = await manager.acceptStream(true);
        expect(Array.from(await stream.read())).toEqual([1]);
        expect((await stream.read()).length).toBe(0); // EOF

        // A second frame at offset 1 with FIN reaches signalFin again; this
        // time finDelivered is already true, so it returns early (line 302).
        manager.dispatch(streamFrame(1n, [2], 1n, true));
        // The new byte is still delivered; EOF still holds.
        expect(Array.from(await stream.read())).toEqual([2]);
        expect((await stream.read()).length).toBe(0);
    });
});
