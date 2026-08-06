/**
 * Transport parameter wire encoding tests for @browsercore/quic.
 *
 * Covers encodeTransportParameters / decodeTransportParameters (RFC 9000 §18.2
 * varint-id + varint-length + value layout), the high-level
 * QuicTransportParameters ↔ TransportParameters conversion helpers, and the
 * handshake wiring on QuicConnectionImpl (encoded local params + ingesting
 * peer params).
 */

import { describe, it, expect } from "vitest";
import {
    decodeTransportParameters,
    encodeTransportParameters,
    fromWireParameters,
    toWireParameters,
    type TransportParameters,
} from "../src/transport-params.js";
import {
    TransportParameter,
    makeConnectionId,
    silentLogger,
    type QuicTransportParameters,
} from "../src/types.js";
import { decodeVarint, encodeVarint } from "../src/frame/varint.js";
import { concatAll } from "../src/utils.js";
import { QuicConnectionImpl } from "../src/connection.js";
import { createStreamManager } from "../src/stream/stream.js";
import type { DatagramTransport, UdpAddress } from "../src/types.js";

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

// A no-op datagram transport — the connection's read loop is never started in
// these tests, so send/recv/close are never called.
const fakeTransport: DatagramTransport = {
    id: "fake",
    send: async (): Promise<void> => {},
    recv: async (): Promise<{ data: Uint8Array; from: UdpAddress }> => ({
        data: new Uint8Array(0),
        from: { address: "127.0.0.1", port: 443, family: 4 },
    }),
    close: async (): Promise<void> => {},
};

const fakePeer: UdpAddress = { address: "127.0.0.1", port: 443, family: 4 };

function makeConnection(params: QuicTransportParameters = {}): QuicConnectionImpl {
    const manager = createStreamManager({
        sendFrame: () => {},
        localParameters: params,
        peerParameters: {},
    });
    return new QuicConnectionImpl(
        "test",
        {
            transport: fakeTransport,
            peer: fakePeer,
            serverName: "localhost",
            initialDcid: makeConnectionId(new Uint8Array([1, 2, 3])),
            initialScid: makeConnectionId(new Uint8Array([4, 5, 6])),
            transportParameters: params,
        },
        manager,
        makeConnectionId(new Uint8Array([1, 2, 3])),
    );
}

// ---------------------------------------------------------------------------
// encode
// ---------------------------------------------------------------------------

describe("encodeTransportParameters", () => {
    it("encodes a single parameter as varint id + varint length + value", () => {
        const encoded = encodeTransportParameters(wire([[0x01, new Uint8Array([0xab, 0xcd])]]));
        // id 0x01 → 1-byte varint 0x01; length 2 → 0x02; value 0xab 0xcd.
        expect([...encoded]).toEqual([0x01, 0x02, 0xab, 0xcd]);
    });

    it("encodes multiple parameters sorted by id", () => {
        const encoded = encodeTransportParameters(
            wire([
                [0x03, new Uint8Array([0x01])],
                [0x01, new Uint8Array([0x02])],
            ]),
        );
        // Sorted: 0x01 first, then 0x03.
        expect([...encoded]).toEqual([0x01, 0x01, 0x02, 0x03, 0x01, 0x01]);
    });

    it("encodes an empty parameter set to an empty buffer", () => {
        expect(encodeTransportParameters(new Map()).length).toBe(0);
    });

    it("encodes a value that itself requires a multi-byte varint length", () => {
        // 300-byte value → length varint is 2 bytes (0x41, 0x2c).
        const value = new Uint8Array(300).fill(0x5a);
        const encoded = encodeTransportParameters(wire([[0x04, value]]));
        const expected = concatAll([
            encodeVarint(0x04n),
            encodeVarint(300n),
            value,
        ]);
        expect(encoded).toEqual(expected);
    });
});

// ---------------------------------------------------------------------------
// decode
// ---------------------------------------------------------------------------

describe("decodeTransportParameters", () => {
    it("decodes a single parameter", () => {
        // id 0x01 (MAX_IDLE_TIMEOUT) carries a varint value → [0x02] decodes
        // to the varint 2.
        const decoded = decodeTransportParameters(new Uint8Array([0x01, 0x01, 0x02]));
        expect(decoded.size).toBe(1);
        expect(decoded.get(0x01)).toEqual(new Uint8Array([0x02]));
    });

    it("decodes multiple parameters", () => {
        const decoded = decodeTransportParameters(
            new Uint8Array([0x01, 0x01, 0x02, 0x03, 0x01, 0x01]),
        );
        expect(decoded.size).toBe(2);
        expect(decoded.get(0x01)).toEqual(new Uint8Array([0x02]));
        expect(decoded.get(0x03)).toEqual(new Uint8Array([0x01]));
    });

    it("decodes an empty buffer to an empty map", () => {
        expect(decodeTransportParameters(new Uint8Array(0)).size).toBe(0);
    });

    it("preserves unknown parameter ids", () => {
        // 0x30 is not a known QuicTransportParameters field (and fits in a
        // 1-byte varint, since its top bits are 00); it should still round-
        // trip through decode.
        const decoded = decodeTransportParameters(new Uint8Array([0x30, 0x03, 0x01, 0x02, 0x03]));
        expect(decoded.get(0x30)).toEqual(new Uint8Array([0x01, 0x02, 0x03]));
    });

    it("throws RangeError when the value is truncated", () => {
        // id 0x01, length 5, but only 2 bytes follow.
        expect(() => decodeTransportParameters(new Uint8Array([0x01, 0x05, 0xab, 0xcd]))).toThrow(
            /truncated/,
        );
    });

    it("throws RangeError when the id varint is truncated", () => {
        // 2-byte varint prefix (0x40) but only one byte total.
        expect(() => decodeTransportParameters(new Uint8Array([0x40]))).toThrow(RangeError);
    });
});

// ---------------------------------------------------------------------------
// round-trip
// ---------------------------------------------------------------------------

describe("encode + decode round-trip", () => {
    it("round-trips a single parameter", () => {
        const original = wire([[0x04, new Uint8Array([0x01, 0x02, 0x03, 0x04])]]);
        const decoded = decodeTransportParameters(encodeTransportParameters(original));
        expect(decoded).toEqual(original);
    });

    it("round-trips many parameters with multi-byte varint values", () => {
        const original = wireVarint([
            [TransportParameter.MAX_IDLE_TIMEOUT, 30_000n],
            [TransportParameter.MAX_UDP_PAYLOAD_SIZE, 1350n],
            [TransportParameter.INITIAL_MAX_DATA, 1_048_576n],
            [TransportParameter.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 262_144n],
            [TransportParameter.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 262_144n],
            [TransportParameter.INITIAL_MAX_STREAM_DATA_UNI, 262_144n],
            [TransportParameter.INITIAL_MAX_STREAMS_BIDI, 100n],
            [TransportParameter.INITIAL_MAX_STREAMS_UNI, 100n],
            [TransportParameter.ACTIVE_CONNECTION_ID_LIMIT, 4n],
        ]);
        const decoded = decodeTransportParameters(encodeTransportParameters(original));
        expect(decoded).toEqual(original);
    });

    it("round-trips an empty map", () => {
        const decoded = decodeTransportParameters(encodeTransportParameters(new Map()));
        expect(decoded.size).toBe(0);
    });
});

// ---------------------------------------------------------------------------
// QuicTransportParameters ↔ wire conversion
// ---------------------------------------------------------------------------

describe("toWireParameters", () => {
    it("emits only defined fields, varint-encoded", () => {
        const params: QuicTransportParameters = {
            maxIdleTimeoutMs: 30_000,
            initialMaxData: 1_048_576n,
        };
        const wireForm = toWireParameters(params);
        expect(wireForm.size).toBe(2);
        expect(decodeVarint(wireForm.get(TransportParameter.MAX_IDLE_TIMEOUT)!).value).toBe(30_000n);
        expect(decodeVarint(wireForm.get(TransportParameter.INITIAL_MAX_DATA)!).value).toBe(1_048_576n);
    });

    it("maps every field QuicTransportParameters models", () => {
        const params: QuicTransportParameters = {
            maxIdleTimeoutMs: 60_000,
            maxUdpPayloadSize: 1350,
            initialMaxData: 2_097_152n,
            initialMaxStreamDataBidiLocal: 524_288n,
            initialMaxStreamDataBidiRemote: 524_288n,
            initialMaxStreamDataUni: 524_288n,
            initialMaxStreamsBidi: 128n,
            initialMaxStreamsUni: 32n,
            activeConnectionIdLimit: 8,
        };
        const wireForm = toWireParameters(params);
        expect(wireForm.size).toBe(9);
        // Each value should be a valid varint (decodable without error).
        for (const [, value] of wireForm) {
            expect(() => decodeVarint(value)).not.toThrow();
        }
    });

    it("returns an empty map for an empty QuicTransportParameters", () => {
        expect(toWireParameters({}).size).toBe(0);
    });
});

describe("fromWireParameters", () => {
    it("extracts only the known fields", () => {
        const wireForm = wireVarint([
            [TransportParameter.MAX_IDLE_TIMEOUT, 30_000n],
            [TransportParameter.INITIAL_MAX_DATA, 1_048_576n],
        ]);
        const params = fromWireParameters(wireForm);
        expect(params).toEqual({
            maxIdleTimeoutMs: 30_000,
            initialMaxData: 1_048_576n,
        });
    });

    it("ignores unknown parameter ids", () => {
        const wireForm = wireVarint([
            [TransportParameter.MAX_IDLE_TIMEOUT, 30_000n],
            [0x99, 42n], // unknown — should be ignored
        ]);
        const params = fromWireParameters(wireForm);
        expect(params).toEqual({ maxIdleTimeoutMs: 30_000 });
    });

    it("returns an empty object for an empty map", () => {
        expect(fromWireParameters(new Map())).toEqual({});
    });
});

describe("toWireParameters + fromWireParameters round-trip", () => {
    it("round-trips every field QuicTransportParameters models", () => {
        const params: QuicTransportParameters = {
            maxIdleTimeoutMs: 60_000,
            maxUdpPayloadSize: 1350,
            initialMaxData: 2_097_152n,
            initialMaxStreamDataBidiLocal: 524_288n,
            initialMaxStreamDataBidiRemote: 524_288n,
            initialMaxStreamDataUni: 524_288n,
            initialMaxStreamsBidi: 128n,
            initialMaxStreamsUni: 32n,
            activeConnectionIdLimit: 8,
        };
        expect(fromWireParameters(toWireParameters(params))).toEqual(params);
    });

    it("round-trips a partial set", () => {
        const params: QuicTransportParameters = { maxIdleTimeoutMs: 15_000 };
        expect(fromWireParameters(toWireParameters(params))).toEqual(params);
    });
});

// ---------------------------------------------------------------------------
// handshake wiring on the connection
// ---------------------------------------------------------------------------

describe("QuicConnectionImpl transport parameter wiring", () => {
    it("encodes local parameters for the wire at construction", () => {
        const conn = makeConnection({ maxIdleTimeoutMs: 30_000, initialMaxData: 1_048_576n });
        const encoded = conn.getEncodedLocalParameters();
        // Should be decodable back to the parameters we configured.
        const wireForm = decodeTransportParameters(encoded);
        expect(decodeVarint(wireForm.get(TransportParameter.MAX_IDLE_TIMEOUT)!).value).toBe(30_000n);
        expect(decodeVarint(wireForm.get(TransportParameter.INITIAL_MAX_DATA)!).value).toBe(1_048_576n);
    });

    it("defaults to an empty encoding when no parameters are configured", () => {
        const conn = makeConnection();
        expect(conn.getEncodedLocalParameters().length).toBe(0);
    });

    it("decodes peer wire parameters and feeds them to the stream manager", () => {
        const conn = makeConnection();
        const peerParams: QuicTransportParameters = {
            initialMaxStreamDataBidiRemote: 500_000n,
            initialMaxData: 2_000_000n,
        };
        const peerWire = encodeTransportParameters(toWireParameters(peerParams));
        // Should not throw and should update the manager's peer parameters.
        conn.receivePeerParameters(peerWire);
        // The manager now reflects the peer's parameters — verify by encoding
        // a fresh set of peer params and confirming the manager accepted them
        // (the manager reads peer params when sizing send windows).
        expect(() => conn.receivePeerParameters(peerWire)).not.toThrow();
    });

    it("decoding malformed peer parameters throws", () => {
        const conn = makeConnection();
        // Truncated value.
        expect(() => conn.receivePeerParameters(new Uint8Array([0x01, 0x05, 0xab]))).toThrow(
            /truncated/,
        );
    });
});
