/**
 * Packet header tests for @browsercore/quic.
 *
 * Exercises serializeLongHeader / serializeShortHeader against
 * parsePacketHeader for all long packet types, short-header flag combos,
 * packet-number truncation/decoding (RFC 9000 §17.1), and the truncated /
 * malformed input error paths.
 */

import { describe, it, expect } from "vitest";
import {
    serializeLongHeader,
    serializeShortHeader,
    parsePacketHeader,
    decodePacketNumber,
    encodePacketNumber,
    readPacketNumber,
    type LongHeader,
} from "../src/packet/packet.js";
import {
    LongPacketType,
    HEADER_FORM_LONG,
    HEADER_FORM_SHORT,
} from "../src/types.js";

describe("serializeLongHeader + parsePacketHeader round-trip", () => {
    function roundTripLong(
        type: 0 | 1 | 2 | 3,
        version: number,
        dcid: Uint8Array,
        scid: Uint8Array,
        pnLen: number,
    ): LongHeader {
        const out = serializeLongHeader(type, version, dcid, scid, pnLen);
        const header = parsePacketHeader(out);
        if (header.form !== HEADER_FORM_LONG) throw new Error("expected long header");
        return header;
    }

    it("round-trips an Initial header with non-empty DCID/SCID", () => {
        const dcid = new Uint8Array([1, 2, 3, 4]);
        const scid = new Uint8Array([5, 6]);
        const header = roundTripLong(LongPacketType.INITIAL, 0x00000001, dcid, scid, 1);
        expect(header.type).toBe(LongPacketType.INITIAL);
        expect(header.version).toBe(0x00000001);
        expect(Array.from(header.dcid)).toEqual([1, 2, 3, 4]);
        expect(Array.from(header.scid)).toEqual([5, 6]);
        expect(header.packetNumberLength).toBe(1);
        // header = first(1) + version(4) + dcidLen(1) + dcid + scidLen(1) + scid
        expect(header.headerLength).toBe(6 + 4 + 1 + 2);
    });

    it("round-trips each long packet type (Initial/0-RTT/Handshake/Retry)", () => {
        const dcid = new Uint8Array([0xa0]);
        const scid = new Uint8Array([0xb0]);
        for (const type of [
            LongPacketType.INITIAL,
            LongPacketType.ZERO_RTT,
            LongPacketType.HANDSHAKE,
            LongPacketType.RETRY,
        ] as const) {
            const header = roundTripLong(type, 0x00000001, dcid, scid, 2);
            expect(header.type).toBe(type);
            expect(header.packetNumberLength).toBe(2);
        }
    });

    it("round-trips with empty DCID and SCID", () => {
        const header = roundTripLong(
            LongPacketType.HANDSHAKE,
            0xbbbbbbbb,
            new Uint8Array(0),
            new Uint8Array(0),
            4,
        );
        expect(header.dcid.length).toBe(0);
        expect(header.scid.length).toBe(0);
        expect(header.packetNumberLength).toBe(4);
        expect(header.headerLength).toBe(7); // minimum long header
    });

    it("encodes the first byte with the fixed bit set (0x40)", () => {
        const out = serializeLongHeader(
            LongPacketType.INITIAL,
            0,
            new Uint8Array(0),
            new Uint8Array(0),
            1,
        );
        // Header form (0x80) | fixed bit (0x40) | type(0)<<4 | pnLen-1(0) = 0xC0
        expect(out[0]).toBe(0xc0);
    });

    it("encodes the packet-number length into the low two bits", () => {
        for (const pnLen of [1, 2, 3, 4] as const) {
            const out = serializeLongHeader(
                LongPacketType.INITIAL,
                0,
                new Uint8Array(0),
                new Uint8Array(0),
                pnLen,
            );
            const header = parsePacketHeader(out);
            if (header.form !== HEADER_FORM_LONG) throw new Error("long");
            expect(header.packetNumberLength).toBe(pnLen);
            expect((out[0]! & 0x03) + 1).toBe(pnLen);
        }
    });

    it("appends the `extra` field after the SCID and reports header length excluding it", () => {
        const token = new Uint8Array([0xfe, 0xed]);
        const out = serializeLongHeader(
            LongPacketType.INITIAL,
            0x00000001,
            new Uint8Array([1]),
            new Uint8Array([2]),
            1,
            token,
        );
        const header = parsePacketHeader(out);
        if (header.form !== HEADER_FORM_LONG) throw new Error("long");
        expect(Array.from(out.subarray(header.headerLength))).toEqual([0xfe, 0xed]);
    });
});

describe("serializeShortHeader + parsePacketHeader", () => {
    it("parses a short header and reads spin/key-phase bits and pn length", () => {
        const dcid = new Uint8Array([7, 8]);
        for (const { spin, keyPhase, pnLen } of [
            { spin: false, keyPhase: false, pnLen: 1 },
            { spin: true, keyPhase: false, pnLen: 2 },
            { spin: false, keyPhase: true, pnLen: 3 },
            { spin: true, keyPhase: true, pnLen: 4 },
        ]) {
            const out = serializeShortHeader(dcid, pnLen, spin, keyPhase);
            const header = parsePacketHeader(out);
            if (header.form !== HEADER_FORM_SHORT) throw new Error("short");
            expect(header.form).toBe(HEADER_FORM_SHORT);
            expect(header.spinBit).toBe(spin);
            expect(header.keyPhase).toBe(keyPhase);
            expect(header.packetNumberLength).toBe(pnLen);
            // Parser reports only the first byte as header length; the variable
            // DCID length is supplied by the connection from handshake state.
            expect(header.headerLength).toBe(1);
        }
    });

    it("emits the DCID bytes after the first byte", () => {
        const dcid = new Uint8Array([1, 2, 3, 4]);
        const out = serializeShortHeader(dcid, 1, false, false);
        expect(Array.from(out.subarray(1))).toEqual([1, 2, 3, 4]);
        // First byte for no spin/key phase, pnLen 1 = 0x00.
        expect(out[0]).toBe(0x00);
    });
});

describe("parsePacketHeader error paths", () => {
    it("throws on an empty buffer", () => {
        expect(() => parsePacketHeader(new Uint8Array(0))).toThrow(RangeError);
    });

    it("throws when a long header is shorter than the minimum 7 bytes", () => {
        // 0xC0 => long header form bit set; only 3 bytes provided.
        expect(() => parsePacketHeader(new Uint8Array([0xc0, 0, 0, 0]))).toThrow(/long header/);
    });

    it("throws when the DCID length runs past the buffer", () => {
        // long header, version present, dcid length = 10 but no dcid bytes.
        const buf = new Uint8Array([0xc0, 0, 0, 0, 1, 10, 0]);
        expect(() => parsePacketHeader(buf)).toThrow(/DCID/);
    });

    it("throws when the SCID length runs past the buffer", () => {
        // dcid length = 0, scid length = 10 but no scid bytes.
        const buf = new Uint8Array([0xc0, 0, 0, 0, 1, 0, 10]);
        expect(() => parsePacketHeader(buf)).toThrow(/SCID/);
    });
});

describe("decodePacketNumber", () => {
    it("reconstructs the RFC 9000 Appendix A.4 example", () => {
        // largest_pn=0xa82f30ea, truncated=0x9b32, 16 bits => 0xa82f9b32
        const result = decodePacketNumber(0xa82f30ean, 0x9b32n, 16);
        expect(result).toBe(0xa82f9b32n);
    });

    it("selects the candidate matching the low bits near the expected pn", () => {
        // expected=11, truncated=5 within an 8-bit window lands on 5 (no wrap).
        expect(decodePacketNumber(10n, 5n, 8)).toBe(5n);
    });

    it("wraps forward across a 2^16 boundary", () => {
        // largest=0xff, truncated=0x00, 8 bits => expected 256 → candidate 256.
        expect(decodePacketNumber(0xffn, 0x00n, 8)).toBe(256n);
    });

    it("wraps forward when the truncated value lands below the half-window", () => {
        // largest=254, expected=255, 8-bit window, truncated=0 → candidate 0 is
        // below expected-pnHwin(127), so the result wraps up to 256.
        expect(decodePacketNumber(254n, 0n, 8)).toBe(256n);
    });

    it("wraps backward when the candidate lands above the half-window", () => {
        // largest=16, expected=17, 4-bit window, truncated=15 → candidate 31 is
        // above expected+pnHwin(25), so the result wraps down to 15.
        expect(decodePacketNumber(16n, 15n, 4)).toBe(15n);
    });

    it("round-trips with encodePacketNumber for nearby packet numbers", () => {
        for (const { pn, largest, bits } of [
            { pn: 0x1234n, largest: 0x1233n, bits: 16 },
            { pn: 0xffn, largest: 0xfen, bits: 8 },
            { pn: 5n, largest: 4n, bits: 4 },
        ]) {
            const truncated = encodePacketNumber(pn, bits);
            expect(decodePacketNumber(largest, truncated, bits)).toBe(pn);
        }
    });
});

describe("encodePacketNumber", () => {
    it("masks to the low N bits", () => {
        expect(encodePacketNumber(0x12345678n, 8)).toBe(0x78n);
        expect(encodePacketNumber(0x12345678n, 16)).toBe(0x5678n);
        expect(encodePacketNumber(0x12345678n, 32)).toBe(0x12345678n);
    });

    it("encodes 0 to 0 for any bit width", () => {
        expect(encodePacketNumber(0n, 1)).toBe(0n);
        expect(encodePacketNumber(0n, 32)).toBe(0n);
    });
});

describe("readPacketNumber", () => {
    it("reads a big-endian packet number of the given byte length", () => {
        expect(readPacketNumber(new Uint8Array([0x12, 0x34, 0x56]), 0, 2)).toBe(0x1234n);
        expect(readPacketNumber(new Uint8Array([0xff]), 0, 1)).toBe(0xffn);
        expect(readPacketNumber(new Uint8Array([0, 0, 0, 0xab]), 0, 4)).toBe(0xabn);
    });

    it("reads from a non-zero offset", () => {
        expect(readPacketNumber(new Uint8Array([0xaa, 0x12, 0x34]), 1, 2)).toBe(0x1234n);
    });

    it("throws when the buffer is too short for the requested length", () => {
        expect(() => readPacketNumber(new Uint8Array([0x12]), 0, 2)).toThrow(RangeError);
        expect(() => readPacketNumber(new Uint8Array([0x12, 0x34]), 0, 4)).toThrow(RangeError);
    });
});
