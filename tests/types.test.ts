/**
 * Stream-id / domain type tests for @browsercore/quic.
 *
 * Covers the makeStreamId range validation (including the error paths left
 * uncovered by the barrel test), the firstStreamId/nextStreamId helpers, and
 * the low-bit classification predicates across every stream type.
 */

import { describe, it, expect } from "vitest";
import {
    makeStreamId,
    nextStreamId,
    firstStreamId,
    streamIdIsBidirectional,
    streamIdIsClientInitiated,
} from "../src/types.js";

describe("makeStreamId", () => {
    it("accepts 0 and the maximum 62-bit value", () => {
        expect(makeStreamId(0n)).toBe(0n);
        expect(makeStreamId((1n << 62n) - 1n)).toBe((1n << 62n) - 1n);
    });

    it("rejects negative values", () => {
        expect(() => makeStreamId(-1n)).toThrow(RangeError);
        expect(() => makeStreamId(-1000n)).toThrow(/out of range/);
    });

    it("rejects values above 2^62 - 1", () => {
        expect(() => makeStreamId(1n << 62n)).toThrow(RangeError);
        expect(() => makeStreamId((1n << 62n) + 5n)).toThrow(/out of range/);
    });
});

describe("firstStreamId", () => {
    it("computes the first id for each of the four stream types", () => {
        // Low 2 bits: bit 1 = direction (0 bidi), bit 0 = initiator (0 client).
        expect(firstStreamId(true, true)).toBe(0n); // client bidi
        expect(firstStreamId(true, false)).toBe(1n); // server bidi
        expect(firstStreamId(false, true)).toBe(2n); // client uni
        expect(firstStreamId(false, false)).toBe(3n); // server uni
    });
});

describe("nextStreamId", () => {
    it("increments by 4 to stay within the same stream type", () => {
        expect(nextStreamId(0n)).toBe(4n); // client bidi
        expect(nextStreamId(1n)).toBe(5n); // server bidi
        expect(nextStreamId(2n)).toBe(6n); // client uni
        expect(nextStreamId(3n)).toBe(7n); // server uni
    });

    it("preserves the type bits across many increments", () => {
        let id = firstStreamId(true, true);
        for (let i = 0; i < 50; i++) id = nextStreamId(id);
        expect(streamIdIsBidirectional(id)).toBe(true);
        expect(streamIdIsClientInitiated(id)).toBe(true);
        expect(id).toBe(200n);
    });
});

describe("stream id classification predicates", () => {
    it("classifies each stream type from its low bits", () => {
        const cases = [
            { id: 0n, bidi: true, client: true },
            { id: 1n, bidi: true, client: false },
            { id: 2n, bidi: false, client: true },
            { id: 3n, bidi: false, client: false },
            { id: 100n, bidi: true, client: true },
            { id: 101n, bidi: true, client: false },
            { id: 102n, bidi: false, client: true },
            { id: 103n, bidi: false, client: false },
        ];
        for (const { id, bidi, client } of cases) {
            expect(streamIdIsBidirectional(makeStreamId(id))).toBe(bidi);
            expect(streamIdIsClientInitiated(makeStreamId(id))).toBe(client);
        }
    });
});
