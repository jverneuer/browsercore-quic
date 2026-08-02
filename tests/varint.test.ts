/**
 * Varint unit tests for @browsercore/quic.
 *
 * Covers the pull-based readVarint, decodeVarint error paths, and the
 * prefixMask helper including its exhaustiveness default.
 */

import { describe, it, expect } from "vitest";
import {
    decodeVarint,
    encodeVarint,
    encodeVarintInto,
    getVarintEncodedLength,
    prefixMask,
    readVarint,
    VARINT_MAX,
} from "../src/frame/varint.js";
import { concatAll } from "../src/utils.js";

describe("getVarintEncodedLength", () => {
    it("rejects negative values", () => {
        expect(() => getVarintEncodedLength(-1n)).toThrow(RangeError);
    });

    it("rejects values above VARINT_MAX", () => {
        expect(() => getVarintEncodedLength(VARINT_MAX + 1n)).toThrow(RangeError);
    });
});

describe("decodeVarint", () => {
    it("throws when the offset is at or past the end of the buffer", () => {
        const buf = new Uint8Array([0x00]);
        expect(() => decodeVarint(buf, 1)).toThrow(/offset 1/);
        expect(() => decodeVarint(buf, 5)).toThrow(/offset 5/);
    });

    it("throws when the buffer is too short for the declared length", () => {
        // Top two bits = 01 => 2-byte varint, but only one byte follow.
        const buf = new Uint8Array([0x40]);
        expect(() => decodeVarint(buf)).toThrow(/2-byte varint/);
    });

    it("throws when a 4-byte varint is truncated after the offset", () => {
        // 10 prefix => 4-byte varint; provide offset 1 + only 2 bytes.
        const buf = new Uint8Array([0x00, 0x80, 0x01]);
        expect(() => decodeVarint(buf, 1)).toThrow(/4-byte varint/);
    });
});

describe("readVarint", () => {
    it("reads a 1-byte varint from a single chunk", async () => {
        const read = async (): Promise<Uint8Array> => new Uint8Array([63]);
        const { value, bytes } = await readVarint(read);
        expect(value).toBe(63n);
        expect(bytes.length).toBe(1);
    });

    it("pulls extra chunks to complete a multi-byte varint", async () => {
        // A real 2-byte varint (1000 = 0x3e8) split across two reads.
        const encoded = encodeVarint(1000n); // => [0x43, 0xe8]
        const chunks: Uint8Array[] = [encoded.subarray(0, 1), encoded.subarray(1, 2)];
        let i = 0;
        const read = async (): Promise<Uint8Array> => chunks[i++]!;
        const { value, bytes } = await readVarint(read);
        expect(value).toBe(1000n);
        expect(Array.from(bytes)).toEqual([0x43, 0xe8]);
    });

    it("concatenates many small chunks into the full varint", async () => {
        const encoded = encodeVarint(1_073_741_824n); // 4-byte form
        // Deliver one byte per read.
        let pos = 0;
        const read = async (): Promise<Uint8Array> => {
            const chunk = encoded.subarray(pos, pos + 1);
            pos += 1;
            return chunk;
        };
        const { value } = await readVarint(read);
        expect(value).toBe(1_073_741_824n);
    });
});

describe("prefixMask", () => {
    it("returns the prefix mask for each encoded length", () => {
        expect(prefixMask(1)).toBe(0x00);
        expect(prefixMask(2)).toBe(0x40);
        expect(prefixMask(4)).toBe(0x80);
        expect(prefixMask(8)).toBe(0xc0);
    });

    it("is consistent with the prefix bits encoded by encodeVarint", () => {
        for (const value of [0n, 64n, 16_384n, 1_073_741_824n]) {
            const encoded = encodeVarint(value);
            const length = getVarintEncodedLength(value);
            expect(encoded[0]! & 0xc0).toBe(prefixMask(length));
        }
    });

    it("its exhaustiveness default throws when reached", () => {
        // 3 is not a valid varint length; the type system forbids this call, so
        // we cast to exercise the assertNever guard — proving the default is a
        // real exhaustive-match fallback, not dead code.
        expect(() => prefixMask(3 as 1 as 1 | 2 | 4 | 8)).toThrow(/Unexpected value/);
    });
});

describe("encodeVarintInto", () => {
    it("writes into a pre-allocated buffer for each length", () => {
        for (const value of [0n, 64n, 16_384n, 1_073_741_824n]) {
            const length = getVarintEncodedLength(value);
            const out = new Uint8Array(length);
            encodeVarintInto(out, value, length);
            expect(out).toEqual(encodeVarint(value));
        }
    });

    it("its exhaustiveness default throws when reached", () => {
        // 3 is not a valid varint length; the type system forbids the call, so
        // we cast to exercise the assertNever guard — proving the default is a
        // real exhaustive-match fallback and not dead code.
        const out = new Uint8Array(3);
        expect(() => encodeVarintInto(out, 0n, 3 as 1 as 1 | 2 | 4 | 8)).toThrow(/Unexpected value/);
    });
});

describe("encodeVarint + decodeVarint round-trip (all lengths)", () => {
    it("round-trips boundary values for each form", () => {
        const cases = [0n, 1n, 63n, 64n, 16_383n, 16_384n, 1_073_741_823n, 1_073_741_824n, VARINT_MAX];
        for (const value of cases) {
            const encoded = encodeVarint(value);
            expect(decodeVarint(encoded).value).toBe(value);
            // concatAll path used by readVarint must also reconstruct the value.
            expect(decodeVarint(concatAll([encoded])).value).toBe(value);
        }
    });
});
