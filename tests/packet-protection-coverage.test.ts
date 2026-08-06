import { describe, it, expect } from "vitest";
import {
    protectPayload,
    unprotectPayload,
    encryptPayload,
    constructNonce,
    type QuicAead,
} from "../src/packet/packet-protection.js";
import { crypto } from "@browsercore/crypto";

/**
 * Targeted coverage for uncovered branches in packet-protection.ts:
 *   - lines 98-99: assertNever(aead) in aeadAlgorithmId (unsupported AEAD)
 *   - line 344:   protectPayload "protected payload too short" guard
 *   - line 390:   unprotectPayload "protected payload too short" guard
 *   - line 420:   encodeBigInt negative-value guard
 */

describe("aeadAlgorithmId unsupported algorithm (lines 98-99)", () => {
    it("encryptPayload throws on unsupported AEAD", () => {
        const aead = "AES-128-CCM" as QuicAead; // cast to bypass TypeScript union
        const key = crypto.randomBytes(16);
        const nonce = crypto.randomBytes(12);
        const plaintext = new TextEncoder().encode("hello");
        const aad = new Uint8Array([0xc0, 0x01]);
        expect(() => encryptPayload(aead, key, nonce, plaintext, aad, crypto)).toThrow();
    });

    it("protectPayload throws on unsupported AEAD", () => {
        const aead = "AES-128-CCM" as QuicAead;
        const secrets = {
            key: crypto.randomBytes(16),
            iv: crypto.randomBytes(12),
            hp: crypto.randomBytes(16),
        };
        const payload = new TextEncoder().encode("hello");
        expect(() => protectPayload(payload, 1n, 1, 0x00, aead, secrets, false, crypto)).toThrow();
    });
});

describe("protectPayload short-payload guard (line 344)", () => {
    it("throws when protected payload is shorter than 20 bytes", () => {
        const aead: QuicAead = "AES-128-GCM";
        const secrets = {
            key: crypto.randomBytes(16),
            iv: crypto.randomBytes(12),
            hp: crypto.randomBytes(16),
        };
        // Protected payload = plaintext + 16-byte AEAD tag. To be < 20 bytes,
        // plaintext must be < 4 bytes. A 3-byte plaintext yields a 19-byte
        // protected payload, which is too short for the 4+16 header sample.
        const payload = new Uint8Array([0x01, 0x02, 0x03]);
        expect(() =>
            protectPayload(payload, 1n, 1, 0x00, aead, secrets, false, crypto),
        ).toThrow(/protected payload too short/i);
    });
});

describe("unprotectPayload short-payload guard (line 390)", () => {
    it("throws when protected payload is shorter than 20 bytes", () => {
        const aead: QuicAead = "AES-128-GCM";
        const secrets = {
            key: crypto.randomBytes(16),
            iv: crypto.randomBytes(12),
            hp: crypto.randomBytes(16),
        };
        // A 19-byte protected payload is too short for the 4+16 sample window.
        const protectedPayload = new Uint8Array(19);
        expect(() =>
            unprotectPayload(0x00, new Uint8Array([0x01]), 1, protectedPayload, false, aead, secrets, crypto),
        ).toThrow(/protected payload too short/i);
    });
});

describe("encodeBigInt negative-value guard (line 420)", () => {
    it("protectPayload throws on negative packet number", () => {
        const aead: QuicAead = "AES-128-GCM";
        const secrets = {
            key: crypto.randomBytes(16),
            iv: crypto.randomBytes(12),
            hp: crypto.randomBytes(16),
        };
        const payload = new TextEncoder().encode("hello");
        // encodeBigInt is called inside protectPayload with the packet number.
        expect(() =>
            protectPayload(payload, -1n, 1, 0x00, aead, secrets, false, crypto),
        ).toThrow(/negative/i);
    });
});
