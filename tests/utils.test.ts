/**
 * Helper unit tests for @browsercore/quic.
 *
 * Covers the small shared helpers in src/utils.ts and the re-exported varint
 * length helper.
 */

import { describe, it, expect } from "vitest";
import { assertNever, concat, concatAll, hex } from "../src/utils.js";

describe("concat", () => {
    it("concatenates two byte arrays", () => {
        const a = new Uint8Array([1, 2]);
        const b = new Uint8Array([3, 4, 5]);
        expect(Array.from(concat(a, b))).toEqual([1, 2, 3, 4, 5]);
    });

    it("handles empty left and right operands", () => {
        const empty = new Uint8Array(0);
        expect(concat(empty, new Uint8Array([9])).length).toBe(1);
        expect(concat(new Uint8Array([9]), empty).length).toBe(1);
        expect(concat(empty, empty).length).toBe(0);
    });
});

describe("concatAll", () => {
    it("concatenates many parts into one", () => {
        const out = concatAll([
            new Uint8Array([1]),
            new Uint8Array([2, 3]),
            new Uint8Array([]),
            new Uint8Array([4]),
        ]);
        expect(Array.from(out)).toEqual([1, 2, 3, 4]);
    });

    it("returns an empty array for no parts", () => {
        expect(concatAll([]).length).toBe(0);
    });
});

describe("hex", () => {
    it("formats bytes as lowercase hex", () => {
        expect(hex(new Uint8Array([0, 1, 255, 16]))).toBe("0001ff10");
    });

    it("formats an empty array as the empty string", () => {
        expect(hex(new Uint8Array(0))).toBe("");
    });
});

describe("assertNever", () => {
    it("throws for any value", () => {
        expect(() => assertNever("oops" as never)).toThrow(/Unexpected value/);
    });
});
