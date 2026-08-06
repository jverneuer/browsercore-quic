/**
 * Barrel coverage test for @browsercore/quic (index.ts — currently at 0%).
 *
 * The barrel (src/index.ts) re-exports the entire public API surface. Importing
 * it and asserting that each export is present and of the right kind exercises
 * the barrel module itself (its top-level export statements are statements that
 * coverage counts) and catches any accidental removal or rename.
 */

import { describe, it, expect } from "vitest";
import * as quic from "../src/index.js";

describe("barrel public API (index.ts)", () => {
    it("re-exports the connection factory + implementation", () => {
        expect(typeof quic.connectQuic).toBe("function");
        expect(quic.QuicConnectionImpl).toBeDefined();
    });

    it("re-exports every typed error class", () => {
        const errors = [
            "ConnectionClosedError",
            "ConnectionClosingError",
            "FlowControlError",
            "FrameParseError",
            "HandshakeTimeoutError",
            "PacketParseError",
            "PacketProtectionError",
            "QuicError",
            "ResetStreamError",
            "StopSendingError",
            "TransportParameterError",
            "TlsHandshakeError",
        ] as const;
        for (const name of errors) {
            expect(quic[name], `missing error export: ${name}`).toBeDefined();
        }
    });

    it("re-exports enum-like constants and stream-id helpers from types.ts", () => {
        expect(quic.LongPacketType).toBeDefined();
        expect(quic.QuicFrameType).toBeDefined();
        expect(quic.TransportParameter).toBeDefined();
        expect(quic.EMPTY_CONNECTION_ID).toBeDefined();
        expect(quic.HEADER_FORM_LONG).toBe(1);
        expect(quic.HEADER_FORM_SHORT).toBe(0);
        expect(quic.MIN_MAX_UDP_PAYLOAD_SIZE).toBe(1200);
        expect(quic.STREAM_FIN_BIT).toBe(0x01);
        expect(quic.STREAM_LEN_BIT).toBe(0x02);
        expect(quic.STREAM_OFF_BIT).toBe(0x04);
        expect(typeof quic.firstStreamId).toBe("function");
        expect(typeof quic.makeConnectionId).toBe("function");
        expect(typeof quic.makeStreamId).toBe("function");
        expect(typeof quic.nextStreamId).toBe("function");
        expect(typeof quic.streamIdIsBidirectional).toBe("function");
        expect(typeof quic.streamIdIsClientInitiated).toBe("function");
        expect(typeof quic.systemClock).toBe("object");
    });

    it("re-exports varint helpers from frame/varint.ts", () => {
        expect(typeof quic.decodeVarint).toBe("function");
        expect(typeof quic.encodeVarint).toBe("function");
        expect(typeof quic.encodeVarintInto).toBe("function");
        expect(typeof quic.getVarintEncodedLength).toBe("function");
        expect(typeof quic.prefixMask).toBe("function");
        expect(quic.VARINT_MAX).toBe((1n << 62n) - 1n);
    });

    it("re-exports frame encode/decode from frame/frame.ts", () => {
        expect(typeof quic.decodeFrame).toBe("function");
        expect(typeof quic.readFrames).toBe("function");
        expect(typeof quic.serializeFrame).toBe("function");
    });

    it("re-exports packet header + packet-number helpers from packet/packet.ts", () => {
        expect(typeof quic.parsePacketHeader).toBe("function");
        expect(typeof quic.serializeShortHeader).toBe("function");
        expect(typeof quic.serializeLongHeader).toBe("function");
        expect(typeof quic.decodePacketNumber).toBe("function");
        expect(typeof quic.encodePacketNumber).toBe("function");
    });

    it("re-exports the stream manager factory from stream/stream.ts", () => {
        expect(typeof quic.createStreamManager).toBe("function");
    });

    it("re-exports byte helpers from utils.ts", () => {
        expect(typeof quic.assertNever).toBe("function");
        expect(typeof quic.concat).toBe("function");
        expect(typeof quic.concatAll).toBe("function");
        expect(typeof quic.hex).toBe("function");
    });

    it("re-exports transport parameter encode/decode from transport-params.ts", () => {
        expect(typeof quic.decodeTransportParameters).toBe("function");
        expect(typeof quic.encodeTransportParameters).toBe("function");
        expect(typeof quic.fromWireParameters).toBe("function");
        expect(typeof quic.toWireParameters).toBe("function");
    });

    it("re-exports packet protection functions from packet/packet-protection.ts", () => {
        expect(typeof quic.constructNonce).toBe("function");
        expect(typeof quic.encryptPayload).toBe("function");
        expect(typeof quic.decryptPayload).toBe("function");
        expect(typeof quic.computeHeaderProtectionMask).toBe("function");
        expect(typeof quic.applyHeaderProtection).toBe("function");
        expect(typeof quic.removeHeaderProtection).toBe("function");
        expect(typeof quic.protectPayload).toBe("function");
        expect(typeof quic.unprotectPayload).toBe("function");
    });

    it("re-exports QUIC key derivation functions + constants from crypto/key-derivation.ts", () => {
        expect(typeof quic.quicHkdfExpandLabel).toBe("function");
        expect(typeof quic.deriveQuicSecrets).toBe("function");
        expect(typeof quic.deriveInitialSecrets).toBe("function");
        expect(quic.INITIAL_SALT_V1).toBeDefined();
        expect(quic.QUIC_IV_LENGTH).toBe(12);
    });

    it("re-exports the QUIC TLS handshake runner + adapter from handshake/index.ts", () => {
        expect(typeof quic.runQuicHandshake).toBe("function");
        expect(typeof quic.adaptQuicStreamToTransport).toBe("function");
        expect(quic.QuicTransportAdapter).toBeDefined();
    });
});
