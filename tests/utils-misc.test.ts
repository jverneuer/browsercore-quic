/**
 * Edge-case tests for @browsercore/quic utils.ts and transport-params.ts.
 *
 * The sibling utils.test.ts and transport-params.test.ts cover the primary
 * happy paths; this file pushes at the boundaries: zero/empty inputs, varint
 * length boundaries, multi-byte parameter ids, truncated length varints, and
 * exhaustiveness-guard behavior across value types.
 */

import { describe, it, expect } from "vitest";
import { assertNever, concat, concatAll, hex } from "../src/utils.js";
import {
    decodeTransportParameters,
    encodeTransportParameters,
    fromWireParameters,
    toWireParameters,
    type TransportParameters,
} from "../src/transport-params.js";
import { TransportParameter, type QuicTransportParameters } from "../src/types.js";
import { decodeVarint, encodeVarint } from "../src/frame/varint.js";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/** Build a TransportParameters map from (id, raw-value) pairs. */
function wire(params: Array<[number, Uint8Array]>): TransportParameters {
    return new Map(params);
}

/** Build a TransportParameters map from (id, varint-value) pairs. */
function wireVarint(params: Array<[number, bigint]>): TransportParameters {
    return new Map(params.map(([id, value]) => [id, encodeVarint(value)]));
}

// ===========================================================================
// utils: concatAll edge cases
// ===========================================================================

describe("concatAll — edge cases", () => {
    it("returns an empty array for a single empty part", () => {
        expect(concatAll([new Uint8Array(0)]).length).toBe(0);
    });

    it("returns an empty array for many empty parts", () => {
        const out = concatAll([
            new Uint8Array(0),
            new Uint8Array(0),
            new Uint8Array(0),
        ]);
        expect(out.length).toBe(0);
    });

    it("concatenates a single non-empty part", () => {
        const out = concatAll([new Uint8Array([7, 8, 9])]);
        expect(Array.from(out)).toEqual([7, 8, 9]);
    });

    it("handles a large number of parts", () => {
        const parts: Uint8Array[] = [];
        for (let i = 0; i < 100; i++) {
            parts.push(new Uint8Array([i]));
        }
        const out = concatAll(parts);
        expect(out.length).toBe(100);
        for (let i = 0; i < 100; i++) {
            expect(out[i]).toBe(i);
        }
    });

    it("handles parts of widely varying sizes", () => {
        const out = concatAll([
            new Uint8Array(0),
            new Uint8Array([1]),
            new Uint8Array(10).fill(2),
            new Uint8Array(0),
            new Uint8Array([3]),
        ]);
        // 0 + 1 + 10 + 0 + 1 = 12 bytes total.
        expect(out.length).toBe(12);
        expect(out[0]).toBe(1);
        for (let i = 1; i <= 10; i++) {
            expect(out[i]).toBe(2);
        }
        expect(out[11]).toBe(3);
    });

    it("does not mutate the input parts", () => {
        const a = new Uint8Array([1, 2]);
        const b = new Uint8Array([3, 4]);
        concatAll([a, b]);
        expect(Array.from(a)).toEqual([1, 2]);
        expect(Array.from(b)).toEqual([3, 4]);
    });
});

// ===========================================================================
// utils: concat edge cases
// ===========================================================================

describe("concat — edge cases", () => {
    it("preserves byte values above 0x80", () => {
        const a = new Uint8Array([0x80, 0xff]);
        const b = new Uint8Array([0x00, 0x7f]);
        expect(Array.from(concat(a, b))).toEqual([0x80, 0xff, 0x00, 0x7f]);
    });

    it("does not share memory between input and output", () => {
        const a = new Uint8Array([1]);
        const b = new Uint8Array([2]);
        const out = concat(a, b);
        // Mutating the output must not touch the inputs.
        out[0] = 99;
        expect(a[0]).toBe(1);
    });
});

// ===========================================================================
// utils: hex edge cases
// ===========================================================================

describe("hex — edge cases", () => {
    it("formats a single zero byte", () => {
        expect(hex(new Uint8Array([0]))).toBe("00");
    });

    it("formats a single byte with high nibble", () => {
        expect(hex(new Uint8Array([0xab]))).toBe("ab");
    });

    it("pads a low-value single byte with a leading zero", () => {
        expect(hex(new Uint8Array([5]))).toBe("05");
        expect(hex(new Uint8Array([15]))).toBe("0f");
    });

    it("formats all 0xff bytes", () => {
        expect(hex(new Uint8Array([0xff, 0xff, 0xff]))).toBe("ffffff");
    });

    it("formats the full 0x00–0xff range", () => {
        const bytes = new Uint8Array(256);
        for (let i = 0; i < 256; i++) {
            bytes[i] = i;
        }
        const out = hex(bytes);
        expect(out.length).toBe(512);
        expect(out.startsWith("00010203040506070809")).toBe(true);
        expect(out.endsWith("f8f9fafbfcfdfeff")).toBe(true);
    });

    it("returns the empty string for a zero-length array", () => {
        expect(hex(new Uint8Array(0))).toBe("");
    });
});

// ===========================================================================
// utils: assertNever edge cases
// ===========================================================================

describe("assertNever — edge cases", () => {
    it("throws an Error instance", () => {
        let caught: unknown;
        try {
            assertNever("x" as never);
        } catch (e) {
            caught = e;
        }
        expect(caught).toBeInstanceOf(Error);
        expect((caught as Error).message).toMatch(/Unexpected value/);
    });

    it("stringifies a null argument in the message", () => {
        expect(() => assertNever(null as never)).toThrow(/null/);
    });

    it("stringifies a numeric argument in the message", () => {
        expect(() => assertNever(42 as never)).toThrow(/42/);
    });

    it("stringifies an object argument in the message", () => {
        expect(() => assertNever({ kind: "z" } as never)).toThrow(/"kind"/);
    });

    it("stringifies an empty-string argument", () => {
        expect(() => assertNever("" as never)).toThrow(/""/);
    });
});

// ===========================================================================
// transport-params: encode edge cases
// ===========================================================================

describe("encodeTransportParameters — edge cases", () => {
    it("encodes a parameter with an empty value (length 0)", () => {
        const encoded = encodeTransportParameters(
            wire([[TransportParameter.MAX_IDLE_TIMEOUT, new Uint8Array(0)]]),
        );
        // id 0x01 → 0x01, length 0 → 0x00, no value bytes.
        expect([...encoded]).toEqual([0x01, 0x00]);
    });

    it("encodes a parameter whose id requires a multi-byte varint (id >= 64)", () => {
        // id 300 requires a 2-byte varint: prefix 01 → 0x41, 0x2c.
        const encoded = encodeTransportParameters(wire([[300, new Uint8Array([0x01])]]));
        const expected = concatAll([encodeVarint(300n), encodeVarint(1n), new Uint8Array([0x01])]);
        expect(encoded).toEqual(expected);
        // Sanity: first byte has the 2-byte prefix.
        expect(encoded[0] >> 6).toBe(0b01);
    });

    it("encodes a parameter whose id requires a 4-byte varint (id >= 2^14)", () => {
        // id 20000 exceeds the 14-bit 2-byte range → 4-byte varint.
        const id = 20_000;
        const encoded = encodeTransportParameters(wire([[id, new Uint8Array([0x01])]]));
        expect(encoded[0] >> 6).toBe(0b10);
        // Round-trip via decode.
        const decoded = decodeTransportParameters(encoded);
        expect(decoded.get(id)).toEqual(new Uint8Array([0x01]));
    });

    it("encodes a value at the 1-byte→2-byte varint length boundary (length 63 vs 64)", () => {
        // Length 63 → 1-byte varint (top bits 00); length 64 → 2-byte varint.
        const val63 = new Uint8Array(63).fill(0x11);
        const val64 = new Uint8Array(64).fill(0x22);
        const enc63 = encodeTransportParameters(wire([[0x01, val63]]));
        const enc64 = encodeTransportParameters(wire([[0x01, val64]]));
        // id(1) + length(1) + 63 value = 65 bytes.
        expect(enc63.length).toBe(65);
        // id(1) + length(2) + 64 value = 67 bytes.
        expect(enc64.length).toBe(67);
    });

    it("encodes a value at the 2-byte→4-byte varint length boundary (length 16383 vs 16384)", () => {
        const val16383 = new Uint8Array(16_383).fill(0x33);
        const val16384 = new Uint8Array(16_384).fill(0x44);
        const enc16383 = encodeTransportParameters(wire([[0x01, val16383]]));
        const enc16384 = encodeTransportParameters(wire([[0x01, val16384]]));
        // id(1) + length(2) + 16383 = 16386.
        expect(enc16383.length).toBe(16_386);
        // id(1) + length(4) + 16384 = 16389.
        expect(enc16384.length).toBe(16_389);
    });

    it("sorts mixed single- and multi-byte varint ids deterministically", () => {
        const encoded = encodeTransportParameters(
            wire([
                [300, new Uint8Array([0xbb])],
                [1, new Uint8Array([0xaa])],
                [5, new Uint8Array([0xcc])],
            ]),
        );
        // Sorted order: 1, 5, 300.
        // id 1 → [0x01], len 1 → [0x01], value [0xaa]
        // id 5 → [0x05], len 1 → [0x01], value [0xcc]
        // id 300 → 2-byte varint, len 1 → [0x01], value [0xbb]
        const id1 = encodeVarint(1n);
        const id5 = encodeVarint(5n);
        const id300 = encodeVarint(300n);
        const expected = concatAll([
            id1,
            encodeVarint(1n),
            new Uint8Array([0xaa]),
            id5,
            encodeVarint(1n),
            new Uint8Array([0xcc]),
            id300,
            encodeVarint(1n),
            new Uint8Array([0xbb]),
        ]);
        expect(encoded).toEqual(expected);
    });
});

// ===========================================================================
// transport-params: decode edge cases
// ===========================================================================

describe("decodeTransportParameters — edge cases", () => {
    it("decodes a parameter with an empty value (length 0)", () => {
        const decoded = decodeTransportParameters(
            new Uint8Array([TransportParameter.MAX_IDLE_TIMEOUT, 0x00]),
        );
        expect(decoded.size).toBe(1);
        expect(decoded.get(TransportParameter.MAX_IDLE_TIMEOUT)).toEqual(new Uint8Array(0));
    });

    it("decodes a parameter whose id requires a multi-byte varint", () => {
        // id 300 (2-byte varint 0x41 0x2c), length 1 (0x01), value 0xab.
        const decoded = decodeTransportParameters(new Uint8Array([0x41, 0x2c, 0x01, 0xab]));
        expect(decoded.size).toBe(1);
        expect(decoded.get(300)).toEqual(new Uint8Array([0xab]));
    });

    it("decodes a parameter whose id requires a 4-byte varint", () => {
        const id = 20_000;
        const encoded = encodeTransportParameters(wire([[id, new Uint8Array([0xbe])]]));
        const decoded = decodeTransportParameters(encoded);
        expect(decoded.get(id)).toEqual(new Uint8Array([0xbe]));
    });

    it("throws RangeError when the length varint is truncated after a valid id", () => {
        // id 0x01 (1 byte), then 0x40 starts a 2-byte varint but there is no
        // second byte for the length.
        expect(() => decodeTransportParameters(new Uint8Array([0x01, 0x40]))).toThrow(
            /varint/,
        );
    });

    it("throws RangeError when a 4-byte length varint is truncated", () => {
        // id 0x01, then 0x80 0x01 starts a 4-byte varint but is truncated.
        expect(() => decodeTransportParameters(new Uint8Array([0x01, 0x80, 0x01]))).toThrow(
            RangeError,
        );
    });

    it("throws RangeError when the value extends past the buffer end", () => {
        // id 0x01, length 3, but only 1 byte of value follows.
        expect(() => decodeTransportParameters(new Uint8Array([0x01, 0x03, 0xaa]))).toThrow(
            /truncated/,
        );
    });

    it("decodes a value that ends exactly at the buffer boundary", () => {
        // id 0x01, length 2, exactly 2 value bytes — no truncation.
        const decoded = decodeTransportParameters(new Uint8Array([0x01, 0x02, 0xca, 0xfe]));
        expect(decoded.get(0x01)).toEqual(new Uint8Array([0xca, 0xfe]));
    });

    it("handles an empty-value parameter followed by a real one", () => {
        // id 0x01 length 0 (no value), id 0x04 length 1 value 0xff.
        const decoded = decodeTransportParameters(new Uint8Array([0x01, 0x00, 0x04, 0x01, 0xff]));
        expect(decoded.size).toBe(2);
        expect(decoded.get(0x01)).toEqual(new Uint8Array(0));
        expect(decoded.get(0x04)).toEqual(new Uint8Array([0xff]));
    });
});

// ===========================================================================
// transport-params: toWireParameters / fromWireParameters edge cases
// ===========================================================================

describe("toWireParameters — edge cases", () => {
    it("emits zero-valued numeric fields (falsy but defined)", () => {
        const params: QuicTransportParameters = {
            maxIdleTimeoutMs: 0,
            maxUdpPayloadSize: 0,
            activeConnectionIdLimit: 0,
        };
        const wireForm = toWireParameters(params);
        expect(wireForm.size).toBe(3);
        expect(decodeVarint(wireForm.get(TransportParameter.MAX_IDLE_TIMEOUT)!).value).toBe(0n);
        expect(decodeVarint(wireForm.get(TransportParameter.MAX_UDP_PAYLOAD_SIZE)!).value).toBe(0n);
        expect(
            decodeVarint(wireForm.get(TransportParameter.ACTIVE_CONNECTION_ID_LIMIT)!).value,
        ).toBe(0n);
    });

    it("emits zero-valued bigint fields", () => {
        const params: QuicTransportParameters = {
            initialMaxData: 0n,
            initialMaxStreamDataBidiLocal: 0n,
            initialMaxStreamDataBidiRemote: 0n,
            initialMaxStreamDataUni: 0n,
            initialMaxStreamsBidi: 0n,
            initialMaxStreamsUni: 0n,
        };
        const wireForm = toWireParameters(params);
        expect(wireForm.size).toBe(6);
        for (const [, value] of wireForm) {
            expect(decodeVarint(value).value).toBe(0n);
        }
    });

    it("omits undefined fields but emits zero", () => {
        const params: QuicTransportParameters = {
            maxIdleTimeoutMs: 0,
            // maxUdpPayloadSize intentionally omitted
            initialMaxData: 0n,
            // initialMaxStreamDataBidiLocal intentionally omitted
        };
        const wireForm = toWireParameters(params);
        expect(wireForm.size).toBe(2);
        expect(wireForm.has(TransportParameter.MAX_IDLE_TIMEOUT)).toBe(true);
        expect(wireForm.has(TransportParameter.MAX_UDP_PAYLOAD_SIZE)).toBe(false);
        expect(wireForm.has(TransportParameter.INITIAL_MAX_DATA)).toBe(true);
        expect(wireForm.has(TransportParameter.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL)).toBe(false);
    });

    it("encodes a very large bigint value (near 2^62)", () => {
        // 2^60 is encodable as an 8-byte varint.
        const big = 1n << 60n;
        const params: QuicTransportParameters = { initialMaxData: big };
        const wireForm = toWireParameters(params);
        expect(decodeVarint(wireForm.get(TransportParameter.INITIAL_MAX_DATA)!).value).toBe(big);
    });

    it("encodes a large maxIdleTimeoutMs (2^31)", () => {
        const largeMs = 2_147_483_648; // 2^31, exceeds 14-bit varint range
        const params: QuicTransportParameters = { maxIdleTimeoutMs: largeMs };
        const wireForm = toWireParameters(params);
        expect(
            decodeVarint(wireForm.get(TransportParameter.MAX_IDLE_TIMEOUT)!).value,
        ).toBe(BigInt(largeMs));
    });
});

describe("fromWireParameters — edge cases", () => {
    it("round-trips zero-valued fields without dropping them", () => {
        const params: QuicTransportParameters = {
            maxIdleTimeoutMs: 0,
            maxUdpPayloadSize: 0,
            initialMaxData: 0n,
            initialMaxStreamDataBidiLocal: 0n,
            initialMaxStreamDataBidiRemote: 0n,
            initialMaxStreamDataUni: 0n,
            initialMaxStreamsBidi: 0n,
            initialMaxStreamsUni: 0n,
            activeConnectionIdLimit: 0,
        };
        expect(fromWireParameters(toWireParameters(params))).toEqual(params);
    });

    it("returns 0 for a known id whose value bytes encode a zero varint", () => {
        const wireForm = wireVarint([
            [TransportParameter.MAX_IDLE_TIMEOUT, 0n],
            [TransportParameter.INITIAL_MAX_DATA, 0n],
        ]);
        expect(fromWireParameters(wireForm)).toEqual({
            maxIdleTimeoutMs: 0,
            initialMaxData: 0n,
        });
    });

    it("preserves large bigint values through round-trip", () => {
        const big = (1n << 62n) - 1n; // VARINT_MAX
        const params: QuicTransportParameters = { initialMaxData: big };
        const roundTripped = fromWireParameters(toWireParameters(params));
        expect(roundTripped.initialMaxData).toBe(big);
    });
});

// ===========================================================================
// transport-params: encode + decode round-trip edge cases
// ===========================================================================

describe("encodeTransportParameters + decodeTransportParameters — round-trip edge cases", () => {
    it("round-trips a parameter with an empty value", () => {
        const original = wire([[TransportParameter.INITIAL_MAX_DATA, new Uint8Array(0)]]);
        const decoded = decodeTransportParameters(encodeTransportParameters(original));
        expect(decoded).toEqual(original);
    });

    it("round-trips a mix of empty and non-empty values", () => {
        const original = wire([
            [0x01, new Uint8Array(0)],
            [0x02, new Uint8Array([0xca, 0xfe])],
            [0x03, new Uint8Array(0)],
            [300, new Uint8Array([0x42])],
        ]);
        const decoded = decodeTransportParameters(encodeTransportParameters(original));
        expect(decoded).toEqual(original);
    });

    it("round-trips a parameter with a large value (64 KiB)", () => {
        const value = new Uint8Array(65_536).fill(0x77);
        const original = wire([[TransportParameter.INITIAL_MAX_DATA, value]]);
        const decoded = decodeTransportParameters(encodeTransportParameters(original));
        expect(decoded).toEqual(original);
        expect(decoded.get(TransportParameter.INITIAL_MAX_DATA)!.length).toBe(65_536);
    });

    it("round-trips a value exactly at the 4-byte varint length boundary", () => {
        // Length 2^30 - 1 (just below the 8-byte varint length threshold).
        // Allocate 1 KiB instead to keep the test fast — we still exercise the
        // 4-byte length varint via a direct encoding.
        const id = 0x04;
        const value = new Uint8Array(2048).fill(0x55);
        const original = wire([[id, value]]);
        const decoded = decodeTransportParameters(encodeTransportParameters(original));
        expect(decoded.get(id)).toEqual(value);
    });

    it("preserves a multi-byte varint id through round-trip", () => {
        const original = wire([
            [1, new Uint8Array([0xaa])],
            [300, new Uint8Array([0xbb])],
            [20_000, new Uint8Array([0xcc])],
        ]);
        const decoded = decodeTransportParameters(encodeTransportParameters(original));
        expect(decoded.size).toBe(3);
        expect(decoded.get(1)).toEqual(new Uint8Array([0xaa]));
        expect(decoded.get(300)).toEqual(new Uint8Array([0xbb]));
        expect(decoded.get(20_000)).toEqual(new Uint8Array([0xcc]));
    });
});
