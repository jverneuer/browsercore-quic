/**
 * Edge-case tests for QUIC key derivation (RFC 9001 §5).
 *
 * Targets the error path at key-derivation.ts line 79 — the HKDF-Expand
 * length overflow branch — plus boundary and serialization edge cases in
 * quicHkdfExpandLabel, deriveQuicSecrets, and deriveInitialSecrets.
 */

import { describe, it, expect } from "vitest";
import {
    quicHkdfExpandLabel,
    deriveInitialSecrets,
    deriveQuicSecrets,
    INITIAL_SALT_V1,
    QUIC_IV_LENGTH,
    type InitialSecrets,
    type QuicProtectionSecrets,
} from "../src/crypto/key-derivation.js";
import { crypto, SHA_256, SHA_384 } from "@browsercore/crypto";

// HKDF-Expand allows at most 255 blocks. For a given hash the maximum
// derivable length is 255 * hashLen. These boundaries are the crux of line 79.
const SHA256_MAX = 255 * 32; // 8160
const SHA384_MAX = 255 * 48; // 12240

describe("hkdfExpand length overflow (key-derivation.ts line 79)", () => {
    const secret = crypto.randomBytes(32);

    it("throws RangeError for SHA-256 when length exceeds 255 * 32", () => {
        expect(() =>
            quicHkdfExpandLabel(secret, "key", new Uint8Array(0), SHA256_MAX + 1, SHA_256, crypto),
        ).toThrow(RangeError);
    });

    it("throws RangeError for SHA-384 when length exceeds 255 * 48", () => {
        const secret384 = crypto.randomBytes(48);
        expect(() =>
            quicHkdfExpandLabel(secret384, "key", new Uint8Array(0), SHA384_MAX + 1, SHA_384, crypto),
        ).toThrow(RangeError);
    });

    it("reports the length and hash maximum in the error message", () => {
        try {
            quicHkdfExpandLabel(secret, "key", new Uint8Array(0), SHA256_MAX + 1, SHA_256, crypto);
            expect.unreachable("expected RangeError to be thrown");
        } catch (e) {
            expect(e).toBeInstanceOf(RangeError);
            // Message reads: "HKDF-Expand length 8161 exceeds maximum for hash (255 * 32)"
            expect((e as Error).message).toContain(String(SHA256_MAX + 1));
            expect((e as Error).message).toContain("255 * 32");
        }
    });

    it("does NOT throw at the exact boundary (length === 255 * hashLen)", () => {
        // n = ceil(8160 / 32) = 255, which is the maximum allowed (not > 255).
        const out = quicHkdfExpandLabel(secret, "key", new Uint8Array(0), SHA256_MAX, SHA_256, crypto);
        expect(out.length).toBe(SHA256_MAX);
    });

    it("does NOT throw one byte below the boundary", () => {
        const out = quicHkdfExpandLabel(secret, "key", new Uint8Array(0), SHA256_MAX - 1, SHA_256, crypto);
        expect(out.length).toBe(SHA256_MAX - 1);
    });

    it("throws one byte above the boundary (n flips from 255 to 256)", () => {
        expect(() =>
            quicHkdfExpandLabel(secret, "key", new Uint8Array(0), SHA256_MAX + 1, SHA_256, crypto),
        ).toThrow(/HKDF-Expand length 8161 exceeds maximum/);
    });
});

describe("quicHkdfExpandLabel edge cases", () => {
    const secret = crypto.randomBytes(32);

    it("produces correct output length for a single-block derivation (length === hashLen)", () => {
        const out = quicHkdfExpandLabel(secret, "key", new Uint8Array(0), 32, SHA_256, crypto);
        expect(out.length).toBe(32);
    });

    it("produces correct output length for a multi-block derivation (length > hashLen)", () => {
        // 33 bytes for SHA-256 requires 2 HMAC blocks (ceil(33/32) = 2).
        const out = quicHkdfExpandLabel(secret, "key", new Uint8Array(0), 33, SHA_256, crypto);
        expect(out.length).toBe(33);
    });

    it("returns an empty array for length 0 (no blocks needed)", () => {
        const out = quicHkdfExpandLabel(secret, "key", new Uint8Array(0), 0, SHA_256, crypto);
        expect(out.length).toBe(0);
    });

    it("differs when a non-empty context is supplied", () => {
        const emptyCtx = quicHkdfExpandLabel(secret, "key", new Uint8Array(0), 16, SHA_256, crypto);
        const ctx = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
        const withCtx = quicHkdfExpandLabel(secret, "key", ctx, 16, SHA_256, crypto);
        expect(Buffer.from(emptyCtx).equals(Buffer.from(withCtx))).toBe(false);
    });

    it("uses the 'quic ' prefix even with an empty label", () => {
        // label = "" → the encoded label is just "quic " (5 bytes). The output
        // must still differ from a label that omits the prefix entirely.
        const emptyLabel = quicHkdfExpandLabel(secret, "", new Uint8Array(0), 16, SHA_256, crypto);
        const namedLabel = quicHkdfExpandLabel(secret, "key", new Uint8Array(0), 16, SHA_256, crypto);
        expect(Buffer.from(emptyLabel).equals(Buffer.from(namedLabel))).toBe(false);
    });

    it("is sensitive to the context value (different contexts → different output)", () => {
        const ctxA = new Uint8Array([0x01]);
        const ctxB = new Uint8Array([0x02]);
        const a = quicHkdfExpandLabel(secret, "key", ctxA, 16, SHA_256, crypto);
        const b = quicHkdfExpandLabel(secret, "key", ctxB, 16, SHA_256, crypto);
        expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    });

    it("produces SHA-384-length output when given SHA-384", () => {
        const secret384 = crypto.randomBytes(48);
        const out = quicHkdfExpandLabel(secret384, "key", new Uint8Array(0), 48, SHA_384, crypto);
        expect(out.length).toBe(48);
    });

    it("produces distinct outputs for 'quic key' vs 'quic iv' vs 'quic hp' labels", () => {
        const key = quicHkdfExpandLabel(secret, "key", new Uint8Array(0), 16, SHA_256, crypto);
        const iv = quicHkdfExpandLabel(secret, "iv", new Uint8Array(0), 16, SHA_256, crypto);
        const hp = quicHkdfExpandLabel(secret, "hp", new Uint8Array(0), 16, SHA_256, crypto);
        expect(Buffer.from(key).equals(Buffer.from(iv))).toBe(false);
        expect(Buffer.from(key).equals(Buffer.from(hp))).toBe(false);
        expect(Buffer.from(iv).equals(Buffer.from(hp))).toBe(false);
    });
});

describe("deriveQuicSecrets with different key lengths", () => {
    it("produces key-length output for AES-128 (16 bytes)", () => {
        const trafficSecret = crypto.randomBytes(32);
        const secrets = deriveQuicSecrets(trafficSecret, 16, SHA_256, crypto);
        expect(secrets.key.length).toBe(16);
        expect(secrets.iv.length).toBe(QUIC_IV_LENGTH);
        expect(secrets.hp.length).toBe(16);
    });

    it("produces key-length output for AES-256 / ChaCha20 (32 bytes)", () => {
        const trafficSecret = crypto.randomBytes(32);
        const secrets = deriveQuicSecrets(trafficSecret, 32, SHA_256, crypto);
        expect(secrets.key.length).toBe(32);
        expect(secrets.iv.length).toBe(QUIC_IV_LENGTH);
        expect(secrets.hp.length).toBe(32);
    });

    it("produces key-length output matching the SHA-384 hash length (48 bytes)", () => {
        const trafficSecret = crypto.randomBytes(48);
        const secrets = deriveQuicSecrets(trafficSecret, 48, SHA_384, crypto);
        expect(secrets.key.length).toBe(48);
        expect(secrets.iv.length).toBe(QUIC_IV_LENGTH);
        expect(secrets.hp.length).toBe(48);
    });

    it("produces different secrets for different traffic secrets (same length)", () => {
        const a = deriveQuicSecrets(crypto.randomBytes(32), 16, SHA_256, crypto);
        const b = deriveQuicSecrets(crypto.randomBytes(32), 16, SHA_256, crypto);
        expect(Buffer.from(a.key).equals(Buffer.from(b.key))).toBe(false);
        expect(Buffer.from(a.iv).equals(Buffer.from(b.iv))).toBe(false);
        expect(Buffer.from(a.hp).equals(Buffer.from(b.hp))).toBe(false);
    });

    it("keeps iv fixed at QUIC_IV_LENGTH (12) regardless of key length", () => {
        const for16 = deriveQuicSecrets(crypto.randomBytes(32), 16, SHA_256, crypto);
        const for32 = deriveQuicSecrets(crypto.randomBytes(32), 32, SHA_256, crypto);
        expect(for16.iv.length).toBe(QUIC_IV_LENGTH);
        expect(for32.iv.length).toBe(QUIC_IV_LENGTH);
    });
});

describe("deriveInitialSecrets with different salts and DCIDs", () => {
    const dcid = new Uint8Array([0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);

    it("is deterministic for the RFC 9001 sample DCID (same inputs → same secrets)", () => {
        // RFC 9001 Appendix A uses dcid 8394c8f03e515708 with INITIAL_SALT_V1.
        // The derivation must be stable: two calls with identical inputs match.
        const a = deriveInitialSecrets(dcid, INITIAL_SALT_V1, SHA_256, crypto);
        const b = deriveInitialSecrets(dcid, INITIAL_SALT_V1, SHA_256, crypto);
        expect(Array.from(a.clientInitialSecret)).toEqual(Array.from(b.clientInitialSecret));
        expect(Array.from(a.serverInitialSecret)).toEqual(Array.from(b.serverInitialSecret));
    });

    it("produces hash-length (32-byte) secrets with an all-zeros salt", () => {
        const zeroSalt = new Uint8Array(20); // same length as INITIAL_SALT_V1 but zeroed
        const secrets = deriveInitialSecrets(dcid, zeroSalt, SHA_256, crypto);
        expect(secrets.clientInitialSecret.length).toBe(32);
        expect(secrets.serverInitialSecret.length).toBe(32);
    });

    it("produces hash-length (48-byte) secrets with SHA-384", () => {
        const secrets = deriveInitialSecrets(dcid, INITIAL_SALT_V1, SHA_384, crypto);
        expect(secrets.clientInitialSecret.length).toBe(48);
        expect(secrets.serverInitialSecret.length).toBe(48);
    });

    it("derives different secrets for a longer DCID (20 bytes, max QUIC CID length)", () => {
        const longDcid = crypto.randomBytes(20);
        const secrets = deriveInitialSecrets(longDcid, INITIAL_SALT_V1, SHA_256, crypto);
        expect(secrets.clientInitialSecret.length).toBe(32);
        expect(secrets.serverInitialSecret.length).toBe(32);
        expect(Buffer.from(secrets.clientInitialSecret).equals(Buffer.from(secrets.serverInitialSecret))).toBe(false);
    });

    it("derives different secrets for a short DCID (1 byte)", () => {
        const shortDcid = new Uint8Array([0xab]);
        const secrets = deriveInitialSecrets(shortDcid, INITIAL_SALT_V1, SHA_256, crypto);
        expect(secrets.clientInitialSecret.length).toBe(32);
        expect(secrets.serverInitialSecret.length).toBe(32);
    });

    it("changes output when the salt is entirely different (random salt)", () => {
        const randomSalt = crypto.randomBytes(20);
        const a = deriveInitialSecrets(dcid, INITIAL_SALT_V1, SHA_256, crypto);
        const b = deriveInitialSecrets(dcid, randomSalt, SHA_256, crypto);
        expect(Buffer.from(a.clientInitialSecret).equals(Buffer.from(b.clientInitialSecret))).toBe(false);
        expect(Buffer.from(a.serverInitialSecret).equals(Buffer.from(b.serverInitialSecret))).toBe(false);
    });

    it("keeps client and server secrets distinct", () => {
        const secrets: InitialSecrets = deriveInitialSecrets(dcid, INITIAL_SALT_V1, SHA_256, crypto);
        expect(Buffer.from(secrets.clientInitialSecret).equals(Buffer.from(secrets.serverInitialSecret))).toBe(false);
    });
});
