/**
 * Targeted coverage for the three previously-uncovered `noUncheckedIndexedAccess`
 * guard throws in src/frame/varint.ts:
 *
 *  - line 109 — decodeVarint: buf[offset] === undefined despite offset < length
 *  - line 120 — decodeVarint: buf[offset + i] === undefined mid-loop
 *  - line 139 — readVarint: firstChunk[0] === undefined on a zero-length chunk
 *
 * These branches are unreachable with a plain Uint8Array, so we use Proxy to
 * synthesize an array-like whose numeric index access returns `undefined`.
 */

import { describe, it, expect } from "vitest";
import { decodeVarint, readVarint } from "../src/frame/varint.js";

/**
 * Wrap a Uint8Array in a Proxy that returns `undefined` for the given indices,
 * while leaving all other behavior (length, iteration, etc.) intact. Lets us
 * exercise the `buf[offset] === undefined` guard on line 109 without giving up
 * the real typed-array length and prefix byte.
 */
function withUndefinedAt(buf: Uint8Array, indices: number[]): Uint8Array {
    return new Proxy(buf, {
        get(target, prop) {
            if (typeof prop === "string") {
                const idx = Number(prop);
                if (Number.isInteger(idx) && indices.includes(idx)) {
                    return undefined;
                }
            }
            // Pass `target` as the receiver so TypedArray internal getters (like
            // `length`) run against the real TypedArray — not the Proxy — and
            // don't throw "incompatible receiver".
            return Reflect.get(target, prop, target);
        },
    }) as Uint8Array;
}

describe("decodeVarint — noUncheckedIndexedAccess guard on first byte (line 109)", () => {
    it("throws RangeError when buf[offset] returns undefined even though offset < buf.length", () => {
        // A 1-byte (00-prefix) varint buffer whose index 0 we override to undefined.
        const inner = new Uint8Array([0x00]);
        const buf = withUndefinedAt(inner, [0]);
        expect(() => decodeVarint(buf, 0)).toThrow(/Buffer too short for varint at offset 0/);
    });

    it("throws the same error at a non-zero offset when that slot is undefined", () => {
        // offset 1 is within bounds (length 2) but the indexed access returns undefined.
        const inner = new Uint8Array([0x00, 0x40]);
        const buf = withUndefinedAt(inner, [1]);
        expect(() => decodeVarint(buf, 1)).toThrow(/Buffer too short for varint at offset 1/);
    });
});

describe("decodeVarint — noUncheckedIndexedAccess guard on subsequent bytes (line 120)", () => {
    it("throws RangeError when buf[offset + i] returns undefined mid-loop", () => {
        // First byte 0x40 => 01 prefix => 2-byte varint. Index 1 overridden to undefined
        // so the for-loop's `buf[offset + i]` hits the guard on line 120.
        const inner = new Uint8Array([0x40, 0xff]);
        const buf = withUndefinedAt(inner, [1]);
        // Sanity: buffer length (2) is enough to pass the line 113 check.
        expect(() => decodeVarint(buf, 0)).toThrow(/Buffer too short for 2-byte varint at offset 0/);
    });

    it("triggers the guard on a 4-byte varint when the trailing byte is undefined", () => {
        // 0x80 => 10 prefix => 4-byte varint. Index 3 undefined.
        const inner = new Uint8Array([0x80, 0x00, 0x00, 0x01]);
        const buf = withUndefinedAt(inner, [3]);
        expect(() => decodeVarint(buf, 0)).toThrow(/Buffer too short for 4-byte varint at offset 0/);
    });

    it("triggers the guard on an 8-byte varint when a middle byte is undefined", () => {
        // 0xc0 => 11 prefix => 8-byte varint. Index 5 undefined.
        const inner = new Uint8Array([0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        const buf = withUndefinedAt(inner, [5]);
        expect(() => decodeVarint(buf, 0)).toThrow(/Buffer too short for 8-byte varint at offset 0/);
    });
});

describe("readVarint — noUncheckedIndexedAccess guard on first chunk (line 139)", () => {
    it("throws RangeError when the first chunk's index 0 is undefined", async () => {
        // A zero-length Uint8Array has length 0, so [0] is undefined. This is the
        // realistic way to hit line 139 without needing a Proxy — an empty read.
        const read = async (): Promise<Uint8Array> => new Uint8Array(0);
        await expect(readVarint(read)).rejects.toThrow("Buffer too short for varint");
    });

    it("also triggers via a Proxy-masked first byte returning undefined", async () => {
        // Even with a non-empty first chunk, if index 0 returns undefined we throw.
        const inner = new Uint8Array([0x40, 0x01]);
        const masked = new Proxy(inner, {
            get(target, prop) {
                if (prop === "0") return undefined;
                return Reflect.get(target, prop, target);
            },
        }) as Uint8Array;
        const read = async (): Promise<Uint8Array> => masked;
        await expect(readVarint(read)).rejects.toThrow("Buffer too short for varint");
    });
});
