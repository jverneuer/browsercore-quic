import { describe, it, expect } from "vitest";
import {
    constructNonce,
    encryptPayload,
    decryptPayload,
    computeHeaderProtectionMask,
    applyHeaderProtection,
    removeHeaderProtection,
    protectPayload,
    unprotectPayload,
    type QuicAead,
} from "../src/packet/packet-protection.js";
import { crypto } from "@browsercore/crypto";

describe("constructNonce", () => {
    it("XORs the packet number", () => {
        const iv = new Uint8Array(12).fill(0x42);
        const nonce = constructNonce(iv, 0x01n);
        expect(nonce[11]).toBe(0x43);
    });
    it("handles zero packet number", () => {
        const iv = new Uint8Array(12).fill(0x42);
        const nonce = constructNonce(iv, 0n);
        expect(Array.from(nonce)).toEqual(Array.from(iv));
    });
    it("does not mutate input IV", () => {
        const iv = new Uint8Array(12).fill(0x42);
        constructNonce(iv, 0x01n);
        expect(iv[11]).toBe(0x42);
    });
});

describe("encryptPayload + decryptPayload", () => {
    const algorithms: QuicAead[] = ["AES-128-GCM", "AES-256-GCM", "CHACHA20-POLY1305"];
    for (const aead of algorithms) {
        it(aead + " round-trips", () => {
            const key = crypto.randomBytes(aead === "AES-128-GCM" ? 16 : 32);
            const iv = crypto.randomBytes(12);
            const nonce = constructNonce(iv, 1n);
            const plaintext = new TextEncoder().encode("hello");
            const aad = new Uint8Array([0xc0, 0x01]);
            const ciphertext = encryptPayload(aead, key, nonce, plaintext, aad);
            const decrypted = decryptPayload(aead, key, nonce, ciphertext, aad);
            expect(new TextDecoder().decode(decrypted)).toBe("hello");
        });
        it(aead + " fails with tampered AAD", () => {
            const key = crypto.randomBytes(aead === "AES-128-GCM" ? 16 : 32);
            const iv = crypto.randomBytes(12);
            const nonce = constructNonce(iv, 1n);
            const plaintext = new Uint8Array([1, 2, 3]);
            const aad = new Uint8Array([0xc0, 0x01]);
            const ciphertext = encryptPayload(aead, key, nonce, plaintext, aad);
            expect(() => decryptPayload(aead, key, nonce, ciphertext, new Uint8Array([0xc1, 0x01]))).toThrow();
        });
    }
});

describe("computeHeaderProtectionMask", () => {
    it("produces a 16-byte mask", () => {
        const hpKey = crypto.randomBytes(16);
        const sample = crypto.randomBytes(20);
        const mask = computeHeaderProtectionMask(hpKey, sample);
        expect(mask.length).toBe(16);
    });
    it("throws on short sample", () => {
        const hpKey = crypto.randomBytes(16);
        expect(() => computeHeaderProtectionMask(hpKey, crypto.randomBytes(10))).toThrow(RangeError);
    });
});

describe("applyHeaderProtection + removeHeaderProtection", () => {
    it("round-trips short header", () => {
        const hpKey = crypto.randomBytes(16);
        const sample = crypto.randomBytes(20);
        const mask = computeHeaderProtectionMask(hpKey, sample);
        const applied = applyHeaderProtection(0x43, 0x42n, 1, mask, false);
        const removed = removeHeaderProtection(applied.firstByte, applied.packetNumberBytes, 1, mask, false);
        expect(removed.firstByte).toBe(0x43);
        expect(removed.packetNumber).toBe(0x42n);
    });
    it("round-trips long header", () => {
        const hpKey = crypto.randomBytes(16);
        const sample = crypto.randomBytes(20);
        const mask = computeHeaderProtectionMask(hpKey, sample);
        const applied = applyHeaderProtection(0xc2, 0x1234n, 2, mask, true);
        const removed = removeHeaderProtection(applied.firstByte, applied.packetNumberBytes, 2, mask, true);
        expect(removed.firstByte).toBe(0xc2);
        expect(removed.packetNumber).toBe(0x1234n);
    });
});

describe("protectPayload + unprotectPayload", () => {
    it("round-trips short header AES-128-GCM", () => {
        const aead: QuicAead = "AES-128-GCM";
        const secrets = { key: crypto.randomBytes(16), iv: crypto.randomBytes(12), hp: crypto.randomBytes(16) };
        const payload = new TextEncoder().encode("hello quic");
        const result = protectPayload(payload, 42n, 1, 0x00, aead, secrets, false, crypto);
        const unprotected = unprotectPayload(result.maskedFirstByte, result.maskedPacketNumber, 1, result.protectedPayload, false, aead, secrets, crypto);
        expect(unprotected.packetNumber).toBe(42n);
        expect(new TextDecoder().decode(unprotected.payload)).toBe("hello quic");
    });
    it("round-trips long header AES-256-GCM", () => {
        const aead: QuicAead = "AES-256-GCM";
        const secrets = { key: crypto.randomBytes(32), iv: crypto.randomBytes(12), hp: crypto.randomBytes(32) };
        const payload = new Uint8Array([0x06, 0x00, 0x04, 0x01, 0x02, 0x03]);
        const result = protectPayload(payload, 0n, 1, 0xc0, aead, secrets, true, crypto);
        const unprotected = unprotectPayload(result.maskedFirstByte, result.maskedPacketNumber, 1, result.protectedPayload, true, aead, secrets, crypto);
        expect(unprotected.packetNumber).toBe(0n);
        expect(Array.from(unprotected.payload)).toEqual(Array.from(payload));
    });
    it("fails with wrong key", () => {
        const aead: QuicAead = "AES-128-GCM";
        const secrets = { key: crypto.randomBytes(16), iv: crypto.randomBytes(12), hp: crypto.randomBytes(16) };
        const wrongSecrets = { key: crypto.randomBytes(16), iv: secrets.iv, hp: secrets.hp };
        const payload = new TextEncoder().encode("secret");
        const result = protectPayload(payload, 1n, 1, 0x00, aead, secrets, false, crypto);
        expect(() => unprotectPayload(result.maskedFirstByte, result.maskedPacketNumber, 1, result.protectedPayload, false, aead, wrongSecrets, crypto)).toThrow();
    });
});
