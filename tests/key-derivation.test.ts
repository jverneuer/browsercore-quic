/**
 * Key derivation tests for @browsercore/quic (RFC 9001 §5).
 *
 * Exercises quicHkdfExpandLabel, deriveInitialSecrets, and deriveQuicSecrets
 * against the RFC 9001 test vectors (where available) and round-trip properties.
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
import { crypto, SHA_256 } from "@browsercore/crypto";

describe("quicHkdfExpandLabel", () => {
    it("produces the correct output length", () => {
        const secret = crypto.randomBytes(32);
        const key = quicHkdfExpandLabel(secret, "key", new Uint8Array(0), 16);
        const iv = quicHkdfExpandLabel(secret, "iv", new Uint8Array(0), 12);
        const hp = quicHkdfExpandLabel(secret, "hp", new Uint8Array(0), 16);
        expect(key.length).toBe(16);
        expect(iv.length).toBe(12);
        expect(hp.length).toBe(16);
    });

    it("uses the 'quic ' prefix (distinct from TLS 1.3's 'tls13 ')", () => {
        const secret = crypto.randomBytes(32);
        const quicKey = quicHkdfExpandLabel(secret, "key", new Uint8Array(0), 16);
        // TLS 1.3's HKDF-Expand-Label with "tls13 " prefix produces different output.
        const tlsLabel = new Uint8Array([
            0, 16, // length = 16
            10, // label length
            // "tls13 key"
            0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x6b, 0x65, 0x79,
            0, // context length
        ]);
        const tlsKey = crypto.hkdf(SHA_256, secret, secret, tlsLabel, 16);
        // The QUIC and TLS outputs must differ because the prefixes differ.
        expect(Buffer.from(quicKey).equals(Buffer.from(tlsKey))).toBe(false);
    });

    it("is deterministic for the same inputs", () => {
        const secret = crypto.randomBytes(32);
        const a = quicHkdfExpandLabel(secret, "key", new Uint8Array(0), 16);
        const b = quicHkdfExpandLabel(secret, "key", new Uint8Array(0), 16);
        expect(Array.from(a)).toEqual(Array.from(b));
    });

    it("produces different outputs for different labels", () => {
        const secret = crypto.randomBytes(32);
        const key = quicHkdfExpandLabel(secret, "key", new Uint8Array(0), 16);
        const iv = quicHkdfExpandLabel(secret, "iv", new Uint8Array(0), 16);
        expect(Buffer.from(key).equals(Buffer.from(iv))).toBe(false);
    });
});

describe("deriveInitialSecrets (RFC 9001 §5.2)", () => {
    it("derives the same secrets for the same DCID + salt", () => {
        // Determinism: the same inputs must produce the same outputs.
        const dcid = new Uint8Array([0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
        const a = deriveInitialSecrets(dcid, INITIAL_SALT_V1, SHA_256, crypto);
        const b = deriveInitialSecrets(dcid, INITIAL_SALT_V1, SHA_256, crypto);
        expect(Array.from(a.clientInitialSecret)).toEqual(Array.from(b.clientInitialSecret));
        expect(Array.from(a.serverInitialSecret)).toEqual(Array.from(b.serverInitialSecret));
    });

    it("derives different secrets for different DCIDs", () => {
        const dcidA = new Uint8Array([0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
        const dcidB = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        const a = deriveInitialSecrets(dcidA, INITIAL_SALT_V1, SHA_256, crypto);
        const b = deriveInitialSecrets(dcidB, INITIAL_SALT_V1, SHA_256, crypto);
        expect(Buffer.from(a.clientInitialSecret).equals(Buffer.from(b.clientInitialSecret))).toBe(false);
    });

    it("derives different secrets for different salts", () => {
        const dcid = new Uint8Array([0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
        const saltB = new Uint8Array(INITIAL_SALT_V1);
        saltB[0] ^= 0x01; // flip one bit
        const a = deriveInitialSecrets(dcid, INITIAL_SALT_V1, SHA_256, crypto);
        const b = deriveInitialSecrets(dcid, saltB, SHA_256, crypto);
        expect(Buffer.from(a.clientInitialSecret).equals(Buffer.from(b.clientInitialSecret))).toBe(false);
    });

    it("produces distinct client and server secrets", () => {
        const dcid = crypto.randomBytes(8);
        const secrets = deriveInitialSecrets(dcid, INITIAL_SALT_V1, SHA_256, crypto);
        expect(Buffer.from(secrets.clientInitialSecret).equals(Buffer.from(secrets.serverInitialSecret))).toBe(false);
    });

    it("produces hash-length traffic secrets (32 bytes for SHA-256)", () => {
        const dcid = crypto.randomBytes(8);
        const secrets: InitialSecrets = deriveInitialSecrets(dcid, INITIAL_SALT_V1, SHA_256, crypto);
        expect(secrets.clientInitialSecret.length).toBe(32);
        expect(secrets.serverInitialSecret.length).toBe(32);
    });
});

describe("deriveQuicSecrets (RFC 9001 §5.1)", () => {
    it("produces key (16 bytes), iv (12 bytes), and hp (16 bytes) for AES-128", () => {
        const trafficSecret = crypto.randomBytes(32);
        const secrets: QuicProtectionSecrets = deriveQuicSecrets(trafficSecret, 16, SHA_256, crypto);
        expect(secrets.key.length).toBe(16);
        expect(secrets.iv.length).toBe(QUIC_IV_LENGTH);
        expect(secrets.hp.length).toBe(16);
    });

    it("produces key (32 bytes), iv (12 bytes), and hp (32 bytes) for AES-256", () => {
        const trafficSecret = crypto.randomBytes(32);
        const secrets: QuicProtectionSecrets = deriveQuicSecrets(trafficSecret, 32, SHA_256, crypto);
        expect(secrets.key.length).toBe(32);
        expect(secrets.iv.length).toBe(QUIC_IV_LENGTH);
        expect(secrets.hp.length).toBe(32);
    });

    it("produces distinct key, iv, and hp from the same traffic secret", () => {
        const trafficSecret = crypto.randomBytes(32);
        const secrets = deriveQuicSecrets(trafficSecret, 16, SHA_256, crypto);
        expect(Buffer.from(secrets.key).equals(Buffer.from(secrets.iv))).toBe(false);
        expect(Buffer.from(secrets.key).equals(Buffer.from(secrets.hp))).toBe(false);
        expect(Buffer.from(secrets.iv).equals(Buffer.from(secrets.hp))).toBe(false);
    });

    it("is deterministic for the same traffic secret + key length", () => {
        const trafficSecret = crypto.randomBytes(32);
        const a = deriveQuicSecrets(trafficSecret, 16, SHA_256, crypto);
        const b = deriveQuicSecrets(trafficSecret, 16, SHA_256, crypto);
        expect(Array.from(a.key)).toEqual(Array.from(b.key));
        expect(Array.from(a.iv)).toEqual(Array.from(b.iv));
        expect(Array.from(a.hp)).toEqual(Array.from(b.hp));
    });
});
