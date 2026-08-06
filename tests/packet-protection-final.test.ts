import { describe, it, expect } from "vitest";
import {
    constructNonce,
    encryptPayload,
    decryptPayload,
    applyHeaderProtection,
    removeHeaderProtection,
    protectPayload,
    unprotectPayload,
    type QuicAead,
} from "../src/packet/packet-protection.js";
import { crypto } from "@browsercore/crypto";

/**
 * Targeted coverage for the remaining uncovered lines in packet-protection.ts.
 *
 * The v8 line report (its "Uncovered Line #s" column is truncated to
 * "...157,261,288,299") flags a set of defensive RangeError guards plus the
 * AES-128-GCM dispatch arm. The uncovered statements split into:
 *
 *   REACHABLE (exercised below):
 *     - constructNonce:         IV-length guard
 *     - applyHeaderProtection:  empty-mask + too-short-mask guards
 *     - removeHeaderProtection: empty-mask + too-short-mask guards
 *     - AES-128-GCM encrypt/decrypt dispatch arms (via protectPayload lifecycle)
 *
 *   GENUINELY UNREACHABLE (defensive dead code — cannot be covered):
 *     - constructNonce "nonce index out of bounds": the loop runs for
 *       i in [length-8, length-1] over a 12-byte IV that already passed the
 *       length guard, so nonce[i] is always defined.
 *     - applyHeaderProtection "packet number byte out of bounds" (line 261):
 *       pnBytes is produced by encodeBigInt(packetNumber, pnLength) which
 *       always allocates exactly pnLength bytes, so pnBytes[i] for i < pnLength
 *       is always defined.
 *     - aeadEncrypt / aeadDecrypt switch `default: assertNever(id)`: `id` is
 *       returned by aeadAlgorithmId(), which narrows to the three literal
 *       cipher ids (or throws via assertNever first), so the default arm is
 *       unreachable for any runtime value.
 */

describe("constructNonce IV-length guard", () => {
    it("throws RangeError when the IV is not exactly 12 bytes", () => {
        expect(() => constructNonce(new Uint8Array(8), 1n)).toThrow(RangeError);
        expect(() => constructNonce(new Uint8Array(16), 1n)).toThrow(RangeError);
    });

    it("mentions the expected length in the message", () => {
        expect(() => constructNonce(new Uint8Array(8), 0n)).toThrow(/IV must be 12 bytes/);
    });
});

describe("AES-128-GCM dispatch arm (encryptPayload / decryptPayload)", () => {
    it("round-trips a payload through the AES-128-GCM AEAD arm directly", () => {
        const key = crypto.randomBytes(16);
        const iv = crypto.randomBytes(12);
        const nonce = constructNonce(iv, 7n);
        const plaintext = new TextEncoder().encode("aes-128-gcm payload");
        const aad = new Uint8Array([0xc0, 0x00, 0x01]);

        const ciphertext = encryptPayload("AES-128-GCM", key, nonce, plaintext, aad);
        // AEAD ciphertext is plaintext + 16-byte authentication tag.
        expect(ciphertext.length).toBe(plaintext.length + 16);

        const decrypted = decryptPayload("AES-128-GCM", key, nonce, ciphertext, aad);
        expect(new TextDecoder().decode(decrypted)).toBe("aes-128-gcm payload");
    });

    it("round-trips AES-128-GCM through the public protectPayload / unprotectPayload lifecycle", () => {
        const aead: QuicAead = "AES-128-GCM";
        const secrets = {
            key: crypto.randomBytes(16),
            iv: crypto.randomBytes(12),
            hp: crypto.randomBytes(16),
        };
        const payload = new TextEncoder().encode("protected via aes-128-gcm");

        const result = protectPayload(payload, 99n, 2, 0x43, aead, secrets, false, crypto);
        const back = unprotectPayload(
            result.maskedFirstByte,
            result.maskedPacketNumber,
            2,
            result.protectedPayload,
            false,
            aead,
            secrets,
            crypto,
        );
        expect(back.packetNumber).toBe(99n);
        expect(new TextDecoder().decode(back.payload)).toBe("protected via aes-128-gcm");
    });
});

describe("applyHeaderProtection mask-length guards", () => {
    it("throws RangeError when the mask is empty", () => {
        expect(() => applyHeaderProtection(0x43, 1n, 1, new Uint8Array(0), false)).toThrow(
            /mask is empty/,
        );
    });

    it("throws RangeError when the mask is too short for the packet-number length (short header)", () => {
        // One mask byte covers the first-byte mask only; pnLength 2 needs mask[1].
        const tooShort = new Uint8Array(1).fill(0xab);
        expect(() => applyHeaderProtection(0x43, 0x00ffn, 2, tooShort, false)).toThrow(
            /mask too short for 2-byte packet number/,
        );
    });

    it("throws RangeError when the mask is too short (long header, pnLength 4)", () => {
        const tooShort = new Uint8Array(2).fill(0xab);
        expect(() => applyHeaderProtection(0xc2, 0x01020304n, 4, tooShort, true)).toThrow(
            /mask too short for 4-byte packet number/,
        );
    });

    it("still masks correctly when the mask is exactly long enough", () => {
        // A zero mask is the identity transform.
        const mask = new Uint8Array(5).fill(0);
        const applied = applyHeaderProtection(0xc0, 0x0042n, 2, mask, true);
        expect(applied.firstByte).toBe(0xc0);
        expect(Array.from(applied.packetNumberBytes)).toEqual([0x00, 0x42]);
    });
});

describe("removeHeaderProtection mask-length guards", () => {
    it("throws RangeError when the mask is empty", () => {
        expect(() =>
            removeHeaderProtection(0x43, new Uint8Array([0x01]), 1, new Uint8Array(0), false),
        ).toThrow(/mask is empty/);
    });

    it("throws RangeError when the mask is too short to cover the packet number", () => {
        // Only one mask byte: passes the empty-mask check, then mask[1] is undefined
        // and the "mask / pn byte out of bounds" guard fires.
        const tooShort = new Uint8Array(1).fill(0xab);
        expect(() =>
            removeHeaderProtection(0x43, new Uint8Array([0x01, 0x02]), 2, tooShort, false),
        ).toThrow(/out of bounds/);
    });

    it("round-trips correctly with a full-length mask (long header)", () => {
        const mask = new Uint8Array(5).fill(0);
        const removed = removeHeaderProtection(0xc0, new Uint8Array([0x00, 0x42]), 2, mask, true);
        expect(removed.firstByte).toBe(0xc0);
        expect(removed.packetNumber).toBe(0x42n);
    });
});
