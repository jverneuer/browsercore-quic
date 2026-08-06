/**
 * Barrel coverage tests for @browsercore/quic.
 *
 * The three barrel files — src/index.ts, src/handshake/index.ts, and
 * src/crypto/index.ts — are currently at 0% coverage. They are pure re-export
 * modules (no logic, no side effects beyond the export statements themselves),
 * so coverage counts their top-level `export` statements only. Importing each
 * barrel directly and asserting that every re-exported value is present and of
 * the right kind exercises those statements and catches accidental removal or
 * rename.
 *
 * Also covers src/types.ts lines 450-456 — the three devLogger method bodies
 * that delegate to the global console.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import * as quic from "../src/index.js";
import * as handshake from "../src/handshake/index.js";
import * as crypto from "../src/crypto/index.js";
import { devLogger, silentLogger } from "../src/types.js";

// ===========================================================================
// 1. Main barrel — src/index.ts
// ===========================================================================
describe("main barrel (src/index.ts)", () => {
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

    it("re-exports the logger singletons", () => {
        expect(quic.devLogger).toBeDefined();
        expect(quic.silentLogger).toBeDefined();
        expect(typeof quic.devLogger.debug).toBe("function");
        expect(typeof quic.devLogger.warn).toBe("function");
        expect(typeof quic.devLogger.error).toBe("function");
        expect(typeof quic.silentLogger.debug).toBe("function");
        expect(typeof quic.silentLogger.warn).toBe("function");
        expect(typeof quic.silentLogger.error).toBe("function");
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

// ===========================================================================
// 2. Handshake barrel — src/handshake/index.ts
// ===========================================================================
describe("handshake barrel (src/handshake/index.ts)", () => {
    it("re-exports runQuicHandshake as a function", () => {
        expect(typeof handshake.runQuicHandshake).toBe("function");
    });

    it("re-exports adaptQuicStreamToTransport as a function", () => {
        expect(typeof handshake.adaptQuicStreamToTransport).toBe("function");
    });

    it("re-exports QuicTransportAdapter (a class)", () => {
        expect(handshake.QuicTransportAdapter).toBeDefined();
        // A class is a function under the hood — assert it's constructable-ish
        // (without actually constructing, which needs a QuicStream).
        expect(typeof handshake.QuicTransportAdapter).toBe("function");
        expect(handshake.QuicTransportAdapter.prototype).toBeDefined();
    });

    it("exposes the full handshake value surface (no accidental removals)", () => {
        // Value exports only — type exports (QuicKeyPhase, QuicPhaseSecrets,
        // QuicHandshakeResult) are erased at runtime and can't be checked here.
        const valueExports = [
            "runQuicHandshake",
            "adaptQuicStreamToTransport",
            "QuicTransportAdapter",
        ] as const;
        for (const name of valueExports) {
            expect(
                handshake[name],
                `missing handshake barrel value export: ${name}`,
            ).toBeDefined();
        }
    });
});

// ===========================================================================
// 3. Crypto barrel — src/crypto/index.ts
// ===========================================================================
describe("crypto barrel (src/crypto/index.ts)", () => {
    it("re-exports quicHkdfExpandLabel as a function", () => {
        expect(typeof crypto.quicHkdfExpandLabel).toBe("function");
    });

    it("re-exports deriveQuicSecrets as a function", () => {
        expect(typeof crypto.deriveQuicSecrets).toBe("function");
    });

    it("re-exports deriveInitialSecrets as a function", () => {
        expect(typeof crypto.deriveInitialSecrets).toBe("function");
    });

    it("re-exports INITIAL_SALT_V1 as a byte array constant", () => {
        expect(crypto.INITIAL_SALT_V1).toBeDefined();
        expect(crypto.INITIAL_SALT_V1).toBeInstanceOf(Uint8Array);
        expect(crypto.INITIAL_SALT_V1.length).toBeGreaterThan(0);
    });

    it("re-exports QUIC_IV_LENGTH as the number 12", () => {
        expect(crypto.QUIC_IV_LENGTH).toBe(12);
    });

    it("exposes the full crypto value surface (no accidental removals)", () => {
        // Type exports (QuicProtectionSecrets, InitialSecrets) are erased at
        // runtime. Verify the value exports are all present.
        const valueExports = [
            "quicHkdfExpandLabel",
            "deriveQuicSecrets",
            "deriveInitialSecrets",
            "INITIAL_SALT_V1",
            "QUIC_IV_LENGTH",
        ] as const;
        for (const name of valueExports) {
            expect(
                crypto[name],
                `missing crypto barrel value export: ${name}`,
            ).toBeDefined();
        }
    });
});

// ===========================================================================
// 4. src/types.ts lines 450-456 — devLogger method bodies
// ===========================================================================
describe("devLogger method bodies (src/types.ts:450-456)", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it("delegates debug to console.debug", () => {
        const spy = vi.spyOn(console, "debug").mockImplementation(() => {});
        devLogger.debug("msg", { extra: true });
        expect(spy).toHaveBeenCalledWith("msg", { extra: true });
    });

    it("delegates warn to console.warn", () => {
        const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
        devLogger.warn("msg", 42);
        expect(spy).toHaveBeenCalledWith("msg", 42);
    });

    it("delegates error to console.error", () => {
        const spy = vi.spyOn(console, "error").mockImplementation(() => {});
        const err = new Error("boom");
        devLogger.error("msg", err);
        expect(spy).toHaveBeenCalledWith("msg", err);
    });

    it("forwards a rest-parameter list of arbitrary length", () => {
        const spy = vi.spyOn(console, "debug").mockImplementation(() => {});
        devLogger.debug("a", "b", "c", "d");
        expect(spy).toHaveBeenCalledWith("a", "b", "c", "d");
    });
});

// Sanity: silentLogger remains a no-op alongside devLogger.
describe("silentLogger (src/types.ts)", () => {
    it("is a no-op for debug, warn, and error", () => {
        expect(() => {
            silentLogger.debug("ignored", { extra: true });
            silentLogger.warn("ignored", 42);
            silentLogger.error("ignored", new Error("nope"));
        }).not.toThrow();
    });

    it("returns void from every method", () => {
        expect(silentLogger.debug("x")).toBeUndefined();
        expect(silentLogger.warn("x")).toBeUndefined();
        expect(silentLogger.error("x")).toBeUndefined();
    });
});
