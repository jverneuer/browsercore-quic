/**
 * QUIC transport parameter wire encoding (RFC 9000 §18.2).
 *
 * Each transport parameter is encoded as a varint id, followed by a varint
 * length, followed by that many value bytes. The full parameter set is the
 * concatenation of every encoded parameter. This is the format the TLS
 * handshake carries in the QUIC extension — pure wire logic, no I/O.
 *
 * This module also converts between the high-level `QuicTransportParameters`
 * interface (friendly numbers/bigints) and the wire-friendly
 * `TransportParameters` map (id → raw value bytes) that encode/decode operate
 * on. Only the parameters `QuicTransportParameters` models are converted; any
 * other ids preserved in a `TransportParameters` map pass through encode and
 * decode untouched.
 */

import { TransportParameter, type QuicTransportParameters } from "./types.js";
import { decodeVarint, encodeVarint } from "./frame/varint.js";
import { concatAll } from "./utils.js";

/** Wire-friendly transport parameters: parameter id → raw value bytes. */
export type TransportParameters = ReadonlyMap<number, Uint8Array>;

/** Encode wire-format transport parameters to the on-the-wire byte layout. */
export function encodeTransportParameters(params: TransportParameters): Uint8Array {
    // Sort by id for deterministic encoding (RFC 9000 §18.2 does not require
    // order, but deterministic output makes testing + interop predictable).
    const entries = [...params.entries()].sort((a, b) => a[0] - b[0]);
    const parts: Uint8Array[] = [];
    for (const [id, value] of entries) {
        parts.push(encodeVarint(BigInt(id)), encodeVarint(BigInt(value.length)), value);
    }
    return concatAll(parts);
}

/**
 * Decode on-the-wire transport parameters. Unknown ids are preserved in the
 * returned map so a caller can inspect them; they are simply never converted
 * by {@link fromWireParameters}.
 */
export function decodeTransportParameters(buf: Uint8Array): TransportParameters {
    const params = new Map<number, Uint8Array>();
    let offset = 0;
    while (offset < buf.length) {
        const id = decodeVarint(buf, offset);
        offset += id.length;
        const length = decodeVarint(buf, offset);
        offset += length.length;
        const valueEnd = offset + Number(length.value);
        if (valueEnd > buf.length) {
            throw new RangeError(
                `Transport parameter 0x${id.value.toString(16)}: value truncated (${Number(length.value)} bytes declared, ${buf.length - offset} available)`,
            );
        }
        params.set(Number(id.value), buf.subarray(offset, valueEnd));
        offset = valueEnd;
    }
    return params;
}

/**
 * Convert high-level `QuicTransportParameters` to the wire-friendly map form.
 * Only defined fields are emitted; absent fields are omitted.
 */
export function toWireParameters(params: QuicTransportParameters): TransportParameters {
    const out = new Map<number, Uint8Array>();
    if (params.maxIdleTimeoutMs !== undefined) {
        out.set(TransportParameter.MAX_IDLE_TIMEOUT, encodeVarint(BigInt(params.maxIdleTimeoutMs)));
    }
    if (params.maxUdpPayloadSize !== undefined) {
        out.set(TransportParameter.MAX_UDP_PAYLOAD_SIZE, encodeVarint(BigInt(params.maxUdpPayloadSize)));
    }
    if (params.initialMaxData !== undefined) {
        out.set(TransportParameter.INITIAL_MAX_DATA, encodeVarint(params.initialMaxData));
    }
    if (params.initialMaxStreamDataBidiLocal !== undefined) {
        out.set(
            TransportParameter.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            encodeVarint(params.initialMaxStreamDataBidiLocal),
        );
    }
    if (params.initialMaxStreamDataBidiRemote !== undefined) {
        out.set(
            TransportParameter.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            encodeVarint(params.initialMaxStreamDataBidiRemote),
        );
    }
    if (params.initialMaxStreamDataUni !== undefined) {
        out.set(TransportParameter.INITIAL_MAX_STREAM_DATA_UNI, encodeVarint(params.initialMaxStreamDataUni));
    }
    if (params.initialMaxStreamsBidi !== undefined) {
        out.set(TransportParameter.INITIAL_MAX_STREAMS_BIDI, encodeVarint(params.initialMaxStreamsBidi));
    }
    if (params.initialMaxStreamsUni !== undefined) {
        out.set(TransportParameter.INITIAL_MAX_STREAMS_UNI, encodeVarint(params.initialMaxStreamsUni));
    }
    if (params.activeConnectionIdLimit !== undefined) {
        out.set(
            TransportParameter.ACTIVE_CONNECTION_ID_LIMIT,
            encodeVarint(BigInt(params.activeConnectionIdLimit)),
        );
    }
    return out;
}

/**
 * Convert the wire-friendly map form back to high-level
 * `QuicTransportParameters`. Only the parameters `QuicTransportParameters`
 * models are extracted; unknown ids in the map are ignored.
 */
export function fromWireParameters(params: TransportParameters): QuicTransportParameters {
    // Decode every known id up front, then build the result in one
    // assignment so we never mutate a readonly field mid-construction.
    const maxIdle = params.get(TransportParameter.MAX_IDLE_TIMEOUT);
    const maxUdp = params.get(TransportParameter.MAX_UDP_PAYLOAD_SIZE);
    const initialMaxData = params.get(TransportParameter.INITIAL_MAX_DATA);
    const bidiLocal = params.get(TransportParameter.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);
    const bidiRemote = params.get(TransportParameter.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);
    const uni = params.get(TransportParameter.INITIAL_MAX_STREAM_DATA_UNI);
    const bidiStreams = params.get(TransportParameter.INITIAL_MAX_STREAMS_BIDI);
    const uniStreams = params.get(TransportParameter.INITIAL_MAX_STREAMS_UNI);
    const activeLimit = params.get(TransportParameter.ACTIVE_CONNECTION_ID_LIMIT);
    return {
        ...(maxIdle === undefined ? {} : { maxIdleTimeoutMs: Number(decodeVarint(maxIdle).value) }),
        ...(maxUdp === undefined ? {} : { maxUdpPayloadSize: Number(decodeVarint(maxUdp).value) }),
        ...(initialMaxData === undefined ? {} : { initialMaxData: decodeVarint(initialMaxData).value }),
        ...(bidiLocal === undefined
            ? {}
            : { initialMaxStreamDataBidiLocal: decodeVarint(bidiLocal).value }),
        ...(bidiRemote === undefined
            ? {}
            : { initialMaxStreamDataBidiRemote: decodeVarint(bidiRemote).value }),
        ...(uni === undefined ? {} : { initialMaxStreamDataUni: decodeVarint(uni).value }),
        ...(bidiStreams === undefined
            ? {}
            : { initialMaxStreamsBidi: decodeVarint(bidiStreams).value }),
        ...(uniStreams === undefined ? {} : { initialMaxStreamsUni: decodeVarint(uniStreams).value }),
        ...(activeLimit === undefined
            ? {}
            : { activeConnectionIdLimit: Number(decodeVarint(activeLimit).value) }),
    };
}
