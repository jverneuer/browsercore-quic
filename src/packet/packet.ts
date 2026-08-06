/**
 * QUIC packet header parser and serializer (RFC 9000 §17).
 *
 * Pure wire-format logic — no I/O, no encryption. Two header forms:
 *
 *   Long header (first bit = 1): used during the handshake.
 *     Header form (1) | Fixed bit (1) | Long packet type (2) | Type-specific (2)
 *     | Version (32) | DCID len (8) | DCID (0..255) | SCID len (8) | SCID (0..255)
 *     [+ type-specific fields: Token length/token (Initial), Packet number length, Payload]
 *
 *   Short header (first bit = 0): 1-RTT data after the handshake.
 *     Header form (1) | Fixed bit (1) | Spin bit (1) | Reserved (2) | Key phase (1)
 *     | Packet number length (2) | DCID | Packet number (8/16/24/32 bits) | Protected payload
 *
 * The "packet number length" in both forms occupies the low 2 bits of the
 * first byte (long) or the byte after the DCID (short) and tells the caller how
 * many bytes of packet number follow.
 */

import {
    HEADER_FORM_LONG,
    HEADER_FORM_SHORT,
    LONG_PACKET_TYPE_MASK,
    makeConnectionId,
    type ConnectionId,
    type LongPacketTypeValue,
} from "../types.js";
import { decodeVarint, encodeVarint } from "../frame/varint.js";
import { concatAll } from "../utils.js";

export {
    LongPacketType,
    type LongPacketTypeValue,
} from "../types.js";
export type { ConnectionId } from "../types.js";

/** Parsed long-header fields (pre-decryption). */
export interface LongHeader {
    readonly form: typeof HEADER_FORM_LONG;
    readonly type: LongPacketTypeValue;
    readonly version: number;
    readonly dcid: ConnectionId;
    readonly scid: ConnectionId;
    /** Number of bytes the packet number occupies (1–4). */
    readonly packetNumberLength: number;
    /** Raw bytes consumed by the header (everything before the payload). */
    readonly headerLength: number;
}

/** Parsed short-header (1-RTT) fields (pre-decryption). */
export interface ShortHeader {
    readonly form: typeof HEADER_FORM_SHORT;
    readonly spinBit: boolean;
    readonly keyPhase: boolean;
    readonly dcid: ConnectionId;
    /** Number of bytes the packet number occupies (1–4). */
    readonly packetNumberLength: number;
    readonly headerLength: number;
}

export type PacketHeader = LongHeader | ShortHeader;

/** Serialize a long header (without payload / packet number — caller appends those). */
export function serializeLongHeader(
    type: LongPacketTypeValue,
    version: number,
    dcid: Uint8Array,
    scid: Uint8Array,
    packetNumberLength: number,
    extra: Uint8Array = new Uint8Array(0),
): Uint8Array {
    const first = (HEADER_FORM_LONG << 7) | (1 << 6) | ((type & LONG_PACKET_TYPE_MASK) << 4) | (packetNumberLength - 1);
    const versionBytes = new Uint8Array(4);
    new DataView(versionBytes.buffer).setUint32(0, version);
    return concatAll([
        new Uint8Array([first]),
        versionBytes,
        new Uint8Array([dcid.length]),
        dcid,
        new Uint8Array([scid.length]),
        scid,
        extra,
    ]);
}

/** Serialize a short (1-RTT) header (without payload / packet number). */
export function serializeShortHeader(
    dcid: Uint8Array,
    packetNumberLength: number,
    spinBit: boolean,
    keyPhase: boolean,
): Uint8Array {
    let first = HEADER_FORM_SHORT << 7;
    if (spinBit) {
        first |= 1 << 5;
    }
    if (keyPhase) {
        first |= 1 << 2;
    }
    first |= packetNumberLength - 1;
    return concatAll([new Uint8Array([first]), dcid]);
}

/**
 * Parse a packet header from the start of a buffer. Returns the header and the
 * number of header bytes consumed. Throws PacketParseError on malformed input.
 *
 * Note: this parses the *unprotected* header. In practice the packet number and
 * payload are encrypted; the caller strips header protection before parsing the
 * full packet number. This function parses everything up to (not including) the
 * packet number.
 */
export function parsePacketHeader(buf: Uint8Array): PacketHeader {
    if (buf.length === 0) {
        throw new RangeError("Buffer too short for packet header");
    }
    const first = buf[0];
    if (first === undefined) {
        throw new RangeError("Buffer too short for packet header");
    }
    const form = (first >> 7) & 0x01;

    if (form === HEADER_FORM_LONG) {
        return parseLongHeader(first, buf);
    }
    return parseShortHeader(first, buf);
}

function parseLongHeader(first: number, buf: Uint8Array): LongHeader {
    const type = (first >> 4) & LONG_PACKET_TYPE_MASK;
    const packetNumberLength = (first & 0x03) + 1;
    // Minimum long header: 1 (first) + 4 (version) + 1 (dcid len) + 0 + 1 (scid len) + 0 = 7.
    if (buf.length < 7) {
        throw new RangeError("Buffer too short for long header");
    }
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const version = view.getUint32(1);
    const dcidLen = buf[5];
    if (dcidLen === undefined) {
        throw new RangeError("Buffer too short for DCID");
    }
    if (buf.length < 6 + dcidLen + 1) {
        throw new RangeError("Buffer too short for DCID");
    }
    const dcid = makeConnectionId(buf.subarray(6, 6 + dcidLen));
    const scidLen = buf[6 + dcidLen];
    if (scidLen === undefined) {
        throw new RangeError("Buffer too short for SCID");
    }
    if (buf.length < 6 + dcidLen + 1 + scidLen) {
        throw new RangeError("Buffer too short for SCID");
    }
    const scid = makeConnectionId(buf.subarray(6 + dcidLen + 1, 6 + dcidLen + 1 + scidLen));
    const headerLength = 6 + dcidLen + 1 + scidLen;
    return {
        form: HEADER_FORM_LONG,
        type: type as LongPacketTypeValue,
        version,
        dcid,
        scid,
        packetNumberLength,
        headerLength,
    };
}

function parseShortHeader(first: number, _buf: Uint8Array): ShortHeader {
    const spinBit = ((first >> 5) & 0x01) === 1;
    const keyPhase = ((first >> 2) & 0x01) === 1;
    const packetNumberLength = (first & 0x03) + 1;
    // DCID length is variable and not on the wire for short headers — the
    // caller must know it (from the handshake). We record header length as just
    // the first byte; the DCID is decoded by the connection layer.
    return {
        form: HEADER_FORM_SHORT,
        spinBit,
        keyPhase,
        dcid: makeConnectionId(new Uint8Array(0)),
        packetNumberLength,
        headerLength: 1,
    };
}

/**
 * Decode a truncated packet number to its full value given the expected next
 * packet number (RFC 9000 §17.1). The peer sends the least-significant
 * `encodedBits` bits; we pick the candidate within ±2^(n-1) of `largestPn`
 * that matches those bits.
 */
export function decodePacketNumber(
    largestPn: bigint,
    truncated: bigint,
    encodedBits: number,
): bigint {
    const pnNbits = BigInt(encodedBits);
    const expectedPn = largestPn + 1n;
    const pnWin = 1n << pnNbits;
    const pnHwin = pnWin / 2n;
    const pnMask = pnWin - 1n;
    const candidate = (expectedPn & ~pnMask) | truncated;
    if (candidate <= expectedPn - pnHwin && candidate < (1n << 62n) - pnWin) {
        return candidate + pnWin;
    }
    if (candidate > expectedPn + pnHwin && candidate >= pnWin) {
        return candidate - pnWin;
    }
    return candidate;
}

/** Encode a packet number to its truncated wire form (low `encodedBits` bits). */
export function encodePacketNumber(pn: bigint, encodedBits: number): bigint {
    const mask = (1n << BigInt(encodedBits)) - 1n;
    return pn & mask;
}

/** Read a packet number of the given byte length from a buffer at offset. */
export function readPacketNumber(buf: Uint8Array, offset: number, length: number): bigint {
    let value = 0n;
    for (let i = 0; i < length; i++) {
        const byte = buf[offset + i];
        if (byte === undefined) {
            throw new RangeError(`Buffer too short for packet number at offset ${offset + i}`);
        }
        value = (value << 8n) | BigInt(byte);
    }
    return value;
}

void decodeVarint;
void encodeVarint;
