/**
 * QUIC variable-length integer encoding (RFC 9000 §16).
 *
 * Two-bit prefix selects the length: 1, 2, 4, or 8 bytes. Used for stream ids,
 * frame types, frame lengths, packet numbers, transport-parameter ids/values,
 * and push ids throughout QUIC (and HTTP/3).
 *
 * Pure wire-format logic — no I/O.
 */

import { assertNever, concatAll } from "../utils.js";

/** Maximum value encodable in a QUIC varint (2^62 - 1). */
export const VARINT_MAX = (1n << 62n) - 1n;

/** The length prefix mask in the first byte's top two bits, per encoded length. */
export function prefixMask(length: 1 | 2 | 4 | 8): number {
    switch (length) {
        case 1:
            return 0x00; // 00
        case 2:
            return 0x40; // 01
        case 4:
            return 0x80; // 10
        case 8:
            return 0xc0; // 11
        default:
            return assertNever(length);
    }
}

/** Return the number of bytes needed to encode `value` as a varint. */
export function getVarintEncodedLength(value: bigint): 1 | 2 | 4 | 8 {
    if (value < 0n) {
        throw new RangeError(`varint cannot be negative: ${value}`);
    }
    if (value > VARINT_MAX) {
        throw new RangeError(`varint overflow: ${value}`);
    }
    if (value < (1n << 6n)) {
        return 1;
    }
    if (value < (1n << 14n)) {
        return 2;
    }
    if (value < (1n << 30n)) {
        return 4;
    }
    return 8;
}

/**
 * Write a varint's payload into a pre-allocated buffer of the correct length.
 * The switch is exhaustive over the lengths {@link getVarintEncodedLength} can
 * return; the `default` is a compile-time guard that also serves as a runtime
 * check should the length ever be miscomputed. Exported so the exhaustiveness
 * guard is independently testable (via cast).
 */
export function encodeVarintInto(out: Uint8Array, value: bigint, length: 1 | 2 | 4 | 8): void {
    switch (length) {
        case 1:
            out[0] = prefixMask(1) | Number(value);
            break;
        case 2:
            out[0] = prefixMask(2) | Number((value >> 8n) & 0xffn);
            out[1] = Number(value & 0xffn);
            break;
        case 4:
            out[0] = prefixMask(4) | Number((value >> 24n) & 0xffn);
            out[1] = Number((value >> 16n) & 0xffn);
            out[2] = Number((value >> 8n) & 0xffn);
            out[3] = Number(value & 0xffn);
            break;
        case 8: {
            // Byte 0: 2-bit prefix (11) + top 6 value bits; bytes 1-7: the rest.
            out[0] = prefixMask(8) | Number((value >> 56n) & 0x3fn);
            out[1] = Number((value >> 48n) & 0xffn);
            out[2] = Number((value >> 40n) & 0xffn);
            out[3] = Number((value >> 32n) & 0xffn);
            out[4] = Number((value >> 24n) & 0xffn);
            out[5] = Number((value >> 16n) & 0xffn);
            out[6] = Number((value >> 8n) & 0xffn);
            out[7] = Number(value & 0xffn);
            break;
        }
        default:
            assertNever(length);
    }
}

/** Encode a varint to its wire representation. */
export function encodeVarint(value: bigint): Uint8Array {
    const length = getVarintEncodedLength(value);
    const out = new Uint8Array(length);
    encodeVarintInto(out, value, length);
    return out;
}

/**
 * Decode a varint from the start of `buf`. Returns the value and the number of
 * bytes consumed. Throws RangeError if the buffer is too short.
 */
export function decodeVarint(buf: Uint8Array, offset = 0): { readonly value: bigint; readonly length: number } {
    if (offset >= buf.length) {
        throw new RangeError(`Buffer too short for varint at offset ${offset}`);
    }
    const first = buf[offset];
    if (first === undefined) {
        throw new RangeError(`Buffer too short for varint at offset ${offset}`);
    }
    const length = 1 << ((first >> 6) & 0x03); // 1,2,4,8
    if (buf.length < offset + length) {
        throw new RangeError(`Buffer too short for ${length}-byte varint at offset ${offset}`);
    }
    // Clear the top 2 prefix bits to recover the first 6 payload bits.
    let value = BigInt(first & 0x3f);
    for (let i = 1; i < length; i++) {
        const byte = buf[offset + i];
        if (byte === undefined) {
            throw new RangeError(`Buffer too short for ${length}-byte varint at offset ${offset}`);
        }
        value = (value << 8n) | BigInt(byte);
    }
    return { value, length };
}

/**
 * Read a varint from an async byte source, pulling exactly as many bytes as
 * needed. Used by frame readers that consume a stream incrementally.
 */
export async function readVarint(read: () => Promise<Uint8Array>): Promise<{
    readonly value: bigint;
    readonly bytes: Uint8Array;
}> {
    // Read the first byte to learn the length.
    const firstChunk = await read();
    const first = firstChunk[0];
    if (first === undefined) {
        throw new RangeError("Buffer too short for varint");
    }
    const length = 1 << ((first >> 6) & 0x03);
    // Collect any remaining bytes of the varint.
    const collected: Uint8Array[] = [firstChunk];
    let have = firstChunk.length;
    while (have < length) {
        // Sequential: each read() consumes from the ordered source and we don't
        // know how many chunks are needed until the previous arrives.
        // eslint-disable-next-line no-await-in-loop -- ordered stream consumption, length unknown a priori
        const chunk = await read();
        collected.push(chunk);
        have += chunk.length;
    }
    const all = concatAll(collected);
    const { value } = decodeVarint(all);
    return { value, bytes: all };
}
