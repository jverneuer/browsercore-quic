/**
 * Final-coverage tests for src/packet/packet.ts.
 *
 * Two goals:
 *
 * 1. Exercise `parsePacketHeader` across both header forms — short headers
 *    (all spin/key-phase/pn-length combinations) and long headers built from
 *    *raw* first bytes for every LongPacketType. This walks the form-dispatch
 *    branch and the per-type parsing path independently of the serializer.
 *
 * 2. Cover the three defensive `=== undefined` guards that exist solely to
 *    satisfy `noUncheckedIndexedAccess`:
 *      - line 119: `first`        (buf[0]   undefined after the length>0 check)
 *      - line 140: `dcidLen`      (buf[5]   undefined after the length>=7 check)
 *      - line 148: `scidLen`      (buf[6+n] undefined after the length check)
 *
 *    These branches cannot be reached with a real TypedArray — a non-empty
 *    `Uint8Array` always returns a number for an in-bounds index. We simulate
 *    the impossible "hole" with a Proxy that returns `undefined` for one
 *    chosen index while forwarding every other access (length, buffer,
 *    byteOffset, subarray, other indices) to the backing array.
 */

import { describe, it, expect } from "vitest";
import {
    parsePacketHeader,
    serializeShortHeader,
    type LongHeader,
    type ShortHeader,
} from "../src/packet/packet.js";
import {
    LongPacketType,
    HEADER_FORM_LONG,
    HEADER_FORM_SHORT,
    LONG_PACKET_TYPE_MASK,
    makeConnectionId,
    type LongPacketTypeValue,
} from "../src/types.js";

// ---------------------------------------------------------------------------
// Header-form coverage (form dispatch + per-type parsing from raw bytes)
// ---------------------------------------------------------------------------

describe("parsePacketHeader — header-form coverage", () => {
    it("parses a short header for every spin/key-phase/pn-length combination", () => {
        for (const { spin, keyPhase, pnLen } of [
            { spin: false, keyPhase: false, pnLen: 1 },
            { spin: true, keyPhase: false, pnLen: 2 },
            { spin: false, keyPhase: true, pnLen: 3 },
            { spin: true, keyPhase: true, pnLen: 4 },
        ]) {
            const out = serializeShortHeader(
                makeConnectionId(new Uint8Array([0x01])),
                pnLen,
                spin,
                keyPhase,
            );
            const header = parsePacketHeader(out) as ShortHeader;
            expect(header.form).toBe(HEADER_FORM_SHORT);
            expect(header.spinBit).toBe(spin);
            expect(header.keyPhase).toBe(keyPhase);
            expect(header.packetNumberLength).toBe(pnLen);
            expect(header.headerLength).toBe(1);
        }
    });

    it("parses a long header built from a raw first byte for each LongPacketType", () => {
        const dcid = new Uint8Array([0xaa, 0xbb]);
        const scid = new Uint8Array([0xcc]);
        for (const type of [
            LongPacketType.INITIAL,
            LongPacketType.ZERO_RTT,
            LongPacketType.HANDSHAKE,
            LongPacketType.RETRY,
        ] as const) {
            // First byte: form(1) | fixed(1) | type(2)<<4 | reserved(2) | pnLen-1(2).
            const first =
                (HEADER_FORM_LONG << 7) |
                (1 << 6) |
                ((type & LONG_PACKET_TYPE_MASK) << 4) |
                0b10; // pnLen = 3 (low two bits = 2)
            const buf = new Uint8Array([
                first,
                0x00,
                0x00,
                0x00,
                0x2a, // version = 0x2a
                dcid.length,
                ...dcid,
                scid.length,
                ...scid,
            ]);
            const header = parsePacketHeader(buf) as LongHeader;
            expect(header.form).toBe(HEADER_FORM_LONG);
            expect(header.type).toBe(type as LongPacketTypeValue);
            expect(header.version).toBe(0x2a);
            expect(Array.from(header.dcid)).toEqual([0xaa, 0xbb]);
            expect(Array.from(header.scid)).toEqual([0xcc]);
            expect(header.packetNumberLength).toBe(3);
            expect(header.headerLength).toBe(6 + dcid.length + 1 + scid.length);
        }
    });

    it("dispatches to the short-header path when the form bit is clear", () => {
        // 0x00 first byte => short header, no spin, no key phase, pnLen 1.
        const header = parsePacketHeader(new Uint8Array([0x00, 0x07])) as ShortHeader;
        expect(header.form).toBe(HEADER_FORM_SHORT);
    });
});

// ---------------------------------------------------------------------------
// Defensive `=== undefined` guards (lines 119, 140, 148)
// ---------------------------------------------------------------------------

/**
 * Wrap a real `Uint8Array` so that reading `holeIndex` returns `undefined`
 * (simulating an impossible `noUncheckedIndexedAccess` hole), while every
 * other access behaves exactly like the backing array.
 *
 * TypedArray internals (length/buffer/byteOffset accessors and methods such as
 * `subarray`) reject a Proxy as their receiver, so we forward those to the
 * target directly instead of passing the proxy as the receiver.
 */
function bufferWithHole(backing: Uint8Array, holeIndex: number): Uint8Array {
    // Methods that are invoked as `proxy.method(...)` would bind `this` to the
    // proxy, which TypedArray methods reject — bind them to the backing array.
    const invokeOnTarget = new Set(["subarray", "slice", "set", "fill", "copyWithin"]);
    return new Proxy(backing, {
        get(target, prop) {
            // Numeric index matching the hole => undefined.
            if (typeof prop !== "symbol") {
                const index = Number(prop);
                if (Number.isInteger(index) && index === holeIndex) {
                    return undefined;
                }
                if (typeof prop === "string" && invokeOnTarget.has(prop)) {
                    const fn = target[prop];
                    return typeof fn === "function" ? fn.bind(target) : fn;
                }
            }
            // Forward with the backing array as receiver so TypedArray accessors
            // (length/buffer/byteOffset/byteLength) see a real TypedArray.
            return Reflect.get(target, prop, target);
        },
    }) as unknown as Uint8Array;
}

describe("parsePacketHeader — defensive undefined guards", () => {
    it("throws when buf[0] is undefined despite a non-zero length (line 119)", () => {
        // length is 7 (passes the `length === 0` check) but index 0 is a hole.
        const buf = bufferWithHole(new Uint8Array([0xc0, 0, 0, 0, 1, 0, 0]), 0);
        expect(() => parsePacketHeader(buf)).toThrow(RangeError);
        expect(() => parsePacketHeader(buf)).toThrow(/packet header/);
    });

    it("throws when dcidLen (buf[5]) is undefined despite length >= 7 (line 140)", () => {
        // Valid-looking long header of length 8, but index 5 (dcid length) is a hole.
        const buf = bufferWithHole(new Uint8Array([0xc0, 0, 0, 0, 1, 0xff, 0, 0]), 5);
        expect(() => parsePacketHeader(buf)).toThrow(RangeError);
        expect(() => parsePacketHeader(buf)).toThrow(/DCID/);
    });

    it("throws when scidLen (buf[6 + dcidLen]) is undefined (line 148)", () => {
        // dcidLen (index 5) = 0 so the DCID length check passes and an empty
        // DCID is sliced; the SCID length at index 6 is a hole.
        const buf = bufferWithHole(new Uint8Array([0xc0, 0, 0, 0, 1, 0, 0xff, 0]), 6);
        expect(() => parsePacketHeader(buf)).toThrow(RangeError);
        expect(() => parsePacketHeader(buf)).toThrow(/SCID/);
    });

    it("the hole helper otherwise behaves like a normal buffer", () => {
        // Sanity: only the holed index is undefined; everything else is real.
        const buf = bufferWithHole(new Uint8Array([0xc0, 1, 2, 3, 4, 5, 6, 7]), 0);
        expect(buf.length).toBe(8);
        expect(buf.byteLength).toBe(8);
        expect(buf.byteOffset).toBe(0);
        expect(buf[0]).toBeUndefined();
        expect(buf[1]).toBe(1);
        expect(Array.from(buf.subarray(1, 3))).toEqual([1, 2]);
    });
});
