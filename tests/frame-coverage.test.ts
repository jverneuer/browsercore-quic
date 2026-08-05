/**
 * Targeted coverage tests for @browsercore/quic src/frame/frame.ts.
 *
 * Covers three branches that frame-codec.test.ts exercises only partially:
 *  - Line 214: the noUncheckedIndexedAccess guard in readVarintFromBuffer()
 *              that throws when buffer[0] is undefined despite fill(1) succeeding.
 *  - Line 228: the readBytes() guard that throws when fill(n) fails (truncated body).
 *  - Lines 299-302: the ACK_ECN ack-range loop body (ackRangeCount > 0).
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import * as utils from "../src/utils.js";
import { serializeFrame, decodeFrame, readFrames } from "../src/frame/frame.js";
import { QuicFrameType, type QuicFrame } from "../src/types.js";

/** A reader that yields the whole buffer once, then null forever. */
function fullReader(bytes: Uint8Array): () => Promise<Uint8Array | null> {
    let done = false;
    return () => {
        if (done) return Promise.resolve(null);
        done = true;
        return Promise.resolve(bytes);
    };
}

async function decodeAll(bytes: Uint8Array): Promise<QuicFrame[]> {
    const out: QuicFrame[] = [];
    for await (const f of readFrames(fullReader(bytes))) out.push(f);
    return out;
}

async function firstFrame(frame: QuicFrame): Promise<QuicFrame> {
    const [f] = await decodeAll(serializeFrame(frame));
    if (f === undefined) throw new Error("no frame decoded");
    return f;
}

describe("readVarintFromBuffer noUncheckedIndexedAccess guard (line 214)", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it("throws when buffer[0] is undefined despite fill(1) succeeding", async () => {
        // Mock concat to return a Proxy whose [0] getter returns undefined while
        // length stays >= 1. This is precisely the edge case the
        // noUncheckedIndexedAccess guard on lines 210-214 exists to catch: fill(1)
        // guarantees length >= 1, but the indexed access still narrows to
        // `number | undefined` under the strict compiler flags.
        const realConcat = utils.concat;
        vi.spyOn(utils, "concat").mockImplementation((a: Uint8Array, b: Uint8Array): Uint8Array => {
            const result = realConcat(a, b);
            if (result.length > 0) {
                return new Proxy(result, {
                    get(target, prop) {
                        if (prop === "0") return undefined;
                        return Reflect.get(target, prop);
                    },
                }) as Uint8Array;
            }
            return result;
        });

        // Single PING type byte — fill(1) succeeds via the mocked concat, then
        // readVarintFromBuffer reads buffer[0], hits the undefined guard.
        const it = readFrames(fullReader(new Uint8Array([QuicFrameType.PING])))[
            Symbol.asyncIterator
        ]();
        await expect(it.next()).rejects.toThrow(/unexpected end of frame data/);
    });
});

describe("readBytes fill-failure branch (line 228)", () => {
    it("throws when a CRYPTO frame body is shorter than its length field declares", async () => {
        // CRYPTO wire format: type(0x06) + offset(varint) + length(varint) + data.
        // Here length = 10 but only 5 data bytes follow, so readBytes(10n) fails
        // its fill(n) check and throws at line 227-228.
        const bytes = new Uint8Array([
            0x06, // CRYPTO type
            0x00, // offset = 0
            0x0a, // length = 10
            0x01,
            0x02,
            0x03,
            0x04,
            0x05, // only 5 bytes of data, not 10
        ]);
        const it = readFrames(fullReader(bytes))[Symbol.asyncIterator]();
        await expect(it.next()).rejects.toThrow(/unexpected end of frame data/);
    });

    it("throws when a NEW_TOKEN frame body is shorter than declared", async () => {
        // NEW_TOKEN wire format: type(0x07) + length(varint) + token.
        // length = 8 but only 3 token bytes follow.
        const bytes = new Uint8Array([
            0x07, // NEW_TOKEN type
            0x08, // length = 8
            0xaa,
            0xbb,
            0xcc, // only 3 bytes, not 8
        ]);
        const it = readFrames(fullReader(bytes))[Symbol.asyncIterator]();
        await expect(it.next()).rejects.toThrow(/unexpected end of frame data/);
    });
});

describe("ACK_ECN ack-range loop body (lines 299-302)", () => {
    it("decodes an ACK_ECN frame with one ack range (loop executes once)", async () => {
        const frame = {
            type: QuicFrameType.ACK_ECN as const,
            largestAck: 100n,
            ackDelay: 5n,
            ackRangeCount: 1n,
            firstAckRange: 3n,
            ackRanges: [{ gap: 1n, ackRangeLength: 2n }],
            ecnCounts: { ect0: 10n, ect1: 20n, ce: 30n },
        };
        const decoded = await firstFrame(frame);
        expect(decoded.type).toBe(QuicFrameType.ACK_ECN);
        expect(decoded).toMatchObject({
            largestAck: 100n,
            ackDelay: 5n,
            ackRangeCount: 1n,
            firstAckRange: 3n,
        });
        expect(decoded.ackRanges).toEqual([{ gap: 1n, ackRangeLength: 2n }]);
        expect(decoded.ecnCounts).toEqual({ ect0: 10n, ect1: 20n, ce: 30n });
    });

    it("decodes an ACK_ECN frame with multiple ack ranges (loop iterates multiple times)", async () => {
        const frame = {
            type: QuicFrameType.ACK_ECN as const,
            largestAck: 500n,
            ackDelay: 10n,
            ackRangeCount: 3n,
            firstAckRange: 50n,
            ackRanges: [
                { gap: 1n, ackRangeLength: 2n },
                { gap: 3n, ackRangeLength: 4n },
                { gap: 5n, ackRangeLength: 6n },
            ],
            ecnCounts: { ect0: 100n, ect1: 200n, ce: 300n },
        };
        const decoded = await firstFrame(frame);
        expect(decoded.type).toBe(QuicFrameType.ACK_ECN);
        expect(decoded.ackRanges).toEqual([
            { gap: 1n, ackRangeLength: 2n },
            { gap: 3n, ackRangeLength: 4n },
            { gap: 5n, ackRangeLength: 6n },
        ]);
    });
});
