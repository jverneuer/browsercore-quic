/**
 * Coverage tests for QUIC typed errors (errors.ts lines 169-192).
 *
 * Exercises TlsHandshakeError and PacketProtectionError — the two error
 * classes at the tail of the error hierarchy whose constructors, `kind`
 * discriminators, phase/operation fields, and optional cause chaining were
 * left uncovered by the base errors test.
 */

import { describe, it, expect } from "vitest";
import { TlsHandshakeError, PacketProtectionError } from "../src/errors.js";

describe("TlsHandshakeError", () => {
    it("constructs without a cause and exposes the phase", () => {
        const err = new TlsHandshakeError("client-hello");
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(TlsHandshakeError);
        expect(err.name).toBe("TlsHandshakeError");
        expect(err.kind).toBe("TlsHandshakeError");
        expect(err.phase).toBe("client-hello");
        expect(err.cause).toBeUndefined();
        expect(err.message).toBe("QUIC TLS handshake failed during client-hello");
    });

    it("includes the cause message when a cause is provided", () => {
        const cause = new Error("decrypt_error (alert 50)");
        const err = new TlsHandshakeError("server-finished", { cause });
        expect(err.cause).toBe(cause);
        expect(err.phase).toBe("server-finished");
        expect(err.message).toBe(
            "QUIC TLS handshake failed during server-finished: decrypt_error (alert 50)",
        );
    });

    it("is distinguishable from the base QuicError by kind", () => {
        const err = new TlsHandshakeError("handshake");
        // `kind` is a literal discriminator — switch/if-else on it must not
        // collapse into the base QuicError branch.
        expect(err.kind).not.toBe("QuicError");
        expect(err.kind).toBe("TlsHandshakeError");
    });
});

describe("PacketProtectionError", () => {
    it("constructs for an encrypt operation without a cause", () => {
        const err = new PacketProtectionError("encrypt");
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(PacketProtectionError);
        expect(err.name).toBe("PacketProtectionError");
        expect(err.kind).toBe("PacketProtectionError");
        expect(err.operation).toBe("encrypt");
        expect(err.cause).toBeUndefined();
        expect(err.message).toBe("QUIC packet encrypt failed: authentication mismatch or corrupt input");
    });

    it("constructs for a decrypt operation without a cause", () => {
        const err = new PacketProtectionError("decrypt");
        expect(err.operation).toBe("decrypt");
        expect(err.message).toBe("QUIC packet decrypt failed: authentication mismatch or corrupt input");
    });

    it("wraps an underlying AEAD cause", () => {
        const cause = new Error("AEAD authentication failed");
        const err = new PacketProtectionError("decrypt", { cause });
        expect(err.cause).toBe(cause);
        expect(err.operation).toBe("decrypt");
    });

    it("is distinguishable from TlsHandshakeError by kind", () => {
        const err = new PacketProtectionError("decrypt");
        expect(err.kind).not.toBe("TlsHandshakeError");
        expect(err.kind).toBe("PacketProtectionError");
    });
});
