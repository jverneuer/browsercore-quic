/**
 * QUIC packet protection (RFC 9001 §5).
 *
 * Applies and removes QUIC's two-layer packet protection:
 *
 *   1. Payload encryption (RFC 9001 §5.3): AEAD with quic_key + quic_iv.
 *      The per-record nonce is the XOR of the (zero-padded, big-endian)
 *      packet number into the static IV. The AAD is the unprotected header
 *      (everything up to and including the unencrypted packet number).
 *
 *   2. Header protection (RFC 9001 §5.4): the low bits of the first byte
 *      and the packet number are masked with a mask derived from
 *      AES-ECB(quic_hp, sample). The sample is 16 bytes of ciphertext
 *      starting 4 bytes into the protected payload.
 *
 * This module is pure wire-format logic — no I/O, no key management. It
 * operates over @browsercore/crypto for the AEAD and AES-ECB primitives.
 *
 * Honest limitations:
 *   - Only AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 are wired for
 *     payload AEAD. AES-128-CCM is defined by TLS 1.3 but never negotiated
 *     by QUIC v1, so it is rejected here.
 *   - 0-RTT, KeyUpdate, and key-phase-bit handling are out of scope for now
 *     — the connection layer passes the correct keys for the packet's phase.
 */

import { type CryptoProvider, crypto } from "@browsercore/crypto";
import { QUIC_IV_LENGTH, type QuicProtectionSecrets } from "../crypto/key-derivation.js";
import { concat, assertNever } from "../utils.js";

/**
 * AEAD algorithm identifiers (subset of TLS AEAD algorithms used by QUIC v1).
 * Mirrors @browsercore/tls's AeadAlgorithm naming ("CHACHA20_POLY1305" with
 * underscores). The aeadAlgorithmId helper maps to @browsercore/crypto's
 * "ChaCha20-Poly1305" (hyphens) when calling the crypto provider.
 */
export type QuicAead = "AES-128-GCM" | "AES-256-GCM" | "CHACHA20-POLY1305";

/** AEAD authentication tag length for every cipher QUIC v1 uses (bytes). */
const AEAD_TAG_LENGTH = 16;

/** Header-protection sample length (bytes) per RFC 9001 §5.4.1. */
const HP_SAMPLE_LENGTH = 16;

/** Offset into the protected payload where the sample starts (RFC 9001 §5.4.1). */
const HP_SAMPLE_OFFSET = 4;

/** The byte offsets into the AES-ECB output used for the header-protection mask. */
const HP_MASK_FIRST_BYTE_LEN = 1; // 5 bits (low 5 bits of the first mask byte)
const HP_MASK_PN_OFFSET = 0; // packet number mask starts at byte 0

/** Mask for the low 5 bits of the first header byte (header form, type, reserved, key-phase). */
const FIRST_BYTE_LOW5_MASK = 0x1f;
/** Mask for the low 4 bits of the first header byte (long header: form + fixed + type + pn-len). */
const FIRST_BYTE_LOW4_MASK = 0x0f;

/**
 * Construct the per-packet AEAD nonce from the static IV and the packet number.
 *
 * The packet number is encoded as a zero-padded big-endian integer in an
 * 8-byte buffer, then XOR'd into the IV's low 8 bytes (RFC 9001 §5.3).
 *
 * @param iv  Static IV (12 bytes) derived from the traffic secret.
 * @param pn  Packet number (0..2^62-1).
 */
export function constructNonce(iv: Uint8Array, pn: bigint): Uint8Array {
    if (iv.length !== QUIC_IV_LENGTH) {
        throw new RangeError(`QUIC IV must be ${QUIC_IV_LENGTH} bytes, got ${iv.length}`);
    }
    const nonce = Uint8Array.from(iv);
    // XOR the packet number (big-endian, low 8 bytes) into the IV's low bytes.
    let remaining = pn;
    for (let i = nonce.length - 1; i >= nonce.length - 8 && remaining > 0n; i--) {
        const byte = nonce[i];
        if (byte === undefined) {
            throw new RangeError(`nonce index ${i} out of bounds (iv length ${iv.length})`);
        }
        nonce[i] = byte ^ Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    return nonce;
}

/**
 * Map a QUIC AEAD algorithm name to the @browsercore/crypto symmetric cipher id.
 * QUIC uses "CHACHA20_POLY1305" (underscores, matching @browsercore/tls);
 * @browsercore/crypto expects "ChaCha20-Poly1305" (hyphens).
 */
function aeadAlgorithmId(aead: QuicAead): "AES-128-GCM" | "AES-256-GCM" | "ChaCha20-Poly1305" {
    switch (aead) {
        case "AES-128-GCM":
            return "AES-128-GCM";
        case "AES-256-GCM":
            return "AES-256-GCM";
        case "CHACHA20-POLY1305":
            return "ChaCha20-Poly1305";
        default:
            return assertNever(aead);
    }
}

/**
 * AEAD-encrypt a payload with the given key and nonce.
 *
 * @param aead      AEAD algorithm (AES-128/256-GCM or ChaCha20-Poly1305).
 * @param key       AEAD key (16 bytes for AES-128, 32 bytes for AES-256 / ChaCha20).
 * @param nonce     Per-packet nonce (12 bytes), computed via {@link constructNonce}.
 * @param plaintext The unprotected payload bytes.
 * @param aad       The unprotected header (everything up to and including the
 *                  unencrypted packet number).
 * @param provider  Cryptographic provider.
 * @returns Ciphertext with the 16-byte authentication tag appended.
 */
export function encryptPayload(
    aead: QuicAead,
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array,
    provider: CryptoProvider = crypto,
): Uint8Array {
    return aeadEncrypt(aead, key, nonce, plaintext, aad, provider);
}

/**
 * AEAD-decrypt a payload with the given key and nonce.
 *
 * @param aead      AEAD algorithm.
 * @param key       AEAD key.
 * @param nonce     Per-packet nonce (12 bytes), computed via {@link constructNonce}.
 * @param ciphertext Ciphertext with the 16-byte authentication tag appended.
 * @param aad       The unprotected header (everything up to and including the
 *                  packet number after header protection removal).
 * @param provider  Cryptographic provider.
 * @returns Decrypted plaintext.
 * @throws Error on authentication failure.
 */
export function decryptPayload(
    aead: QuicAead,
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    aad: Uint8Array,
    provider: CryptoProvider = crypto,
): Uint8Array {
    return aeadDecrypt(aead, key, nonce, ciphertext, aad, provider);
}

/** AEAD-encrypt with a concrete @browsercore/crypto cipher id. */
function aeadEncrypt(
    algorithm: QuicAead,
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array,
    provider: CryptoProvider,
): Uint8Array {
    const id = aeadAlgorithmId(algorithm);
    switch (id) {
        case "AES-128-GCM":
            return provider.aes128GcmEncrypt(key, nonce, plaintext, aad);
        case "AES-256-GCM":
            return provider.aes256GcmEncrypt(key, nonce, plaintext, aad);
        case "ChaCha20-Poly1305":
            return provider.chacha20Poly1305Encrypt(key, nonce, plaintext, aad);
        default:
            return assertNever(id);
    }
}

/** AEAD-decrypt with a concrete @browsercore/crypto cipher id. */
function aeadDecrypt(
    algorithm: QuicAead,
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    aad: Uint8Array,
    provider: CryptoProvider,
): Uint8Array {
    const id = aeadAlgorithmId(algorithm);
    switch (id) {
        case "AES-128-GCM":
            return provider.aes128GcmDecrypt(key, nonce, ciphertext, aad);
        case "AES-256-GCM":
            return provider.aes256GcmDecrypt(key, nonce, ciphertext, aad);
        case "ChaCha20-Poly1305":
            return provider.chacha20Poly1305Decrypt(key, nonce, ciphertext, aad);
        default:
            return assertNever(id);
    }
}

/**
 * Derive the header-protection mask for a given sample (RFC 9001 §5.4.1).
 *
 *   mask = AES-ECB(hp_key, sample)
 *
 * The sample is the 16 bytes of (protected) payload starting 4 bytes past
 * the start of the packet number. For short headers (1-RTT), the first byte
 * of the mask is used to protect the low 5 bits of the first header byte
 * (after header protection is removed, these encode the header form + key
 * phase + reserved bits). For long headers, the first byte protects the low
 * 4 bits (header form + fixed + long packet type). Bytes 1–5 of the mask
 * protect the encoded packet number.
 *
 * @param hpKey  Header-protection key (16 bytes for AES-128, 32 bytes for AES-256).
 * @param sample 16-byte sample from the protected payload.
 * @param provider Cryptographic provider.
 * @returns A 16-byte mask; the low 5 (short header) or 4 (long header) bits of
 *          byte 0 protect the first header byte, bytes 1–5 protect the packet
 *          number.
 */
export function computeHeaderProtectionMask(
    hpKey: Uint8Array,
    sample: Uint8Array,
    provider: CryptoProvider = crypto,
): Uint8Array {
    if (sample.length < HP_SAMPLE_LENGTH) {
        throw new RangeError(
            `Header-protection sample must be at least ${HP_SAMPLE_LENGTH} bytes, got ${sample.length}`,
        );
    }
    const block = sample.subarray(0, HP_SAMPLE_LENGTH);
    return provider.aesEcbEncrypt(hpKey, block);
}

/**
 * Apply header protection to the first byte and packet number (RFC 9001 §5.4).
 *
 * @param firstByte      The first header byte (already serialized).
 * @param packetNumber   The packet number to protect.
 * @param pnLength       Number of bytes the packet number occupies on the wire (1–4).
 * @param mask           Header-protection mask (from {@link computeHeaderProtectionMask}).
 * @param isLongHeader   Whether this is a long header (affects which low bits are masked).
 * @returns The masked first byte and masked packet-number bytes.
 */
export function applyHeaderProtection(
    firstByte: number,
    packetNumber: bigint,
    pnLength: number,
    mask: Uint8Array,
    isLongHeader: boolean,
): { firstByte: number; packetNumberBytes: Uint8Array } {
    const firstMaskByte = mask[HP_MASK_PN_OFFSET];
    if (firstMaskByte === undefined) {
        throw new RangeError("header-protection mask is empty");
    }
    const firstByteMask = isLongHeader ? FIRST_BYTE_LOW4_MASK : FIRST_BYTE_LOW5_MASK;
    const maskedFirstByte = firstByte ^ (firstMaskByte & firstByteMask);

    // The packet number is masked with the low (pnLength * 8) bits of mask bytes 1..5.
    const pnBytes = encodeBigInt(packetNumber, pnLength);
    const maskedPnBytes = new Uint8Array(pnLength);
    for (let i = 0; i < pnLength; i++) {
        const maskByte = mask[HP_MASK_FIRST_BYTE_LEN + i];
        if (maskByte === undefined) {
            throw new RangeError(`header-protection mask too short for ${pnLength}-byte packet number`);
        }
        const pnByte = pnBytes[i];
        if (pnByte === undefined) {
            throw new RangeError(`packet number byte ${i} out of bounds`);
        }
        maskedPnBytes[i] = pnByte ^ maskByte;
    }

    return { firstByte: maskedFirstByte, packetNumberBytes: maskedPnBytes };
}

/**
 * Remove header protection from the first byte and packet number (RFC 9001 §5.4).
 *
 * @param firstByte       The first header byte (as received, still masked).
 * @param pnBytes         The masked packet-number bytes (as received).
 * @param pnLength        Number of bytes the packet number occupies (1–4).
 * @param mask            Header-protection mask (from {@link computeHeaderProtectionMask}).
 * @param isLongHeader    Whether this is a long header.
 * @returns The unmasked first byte and packet number.
 */
export function removeHeaderProtection(
    firstByte: number,
    pnBytes: Uint8Array,
    pnLength: number,
    mask: Uint8Array,
    isLongHeader: boolean,
): { firstByte: number; packetNumber: bigint } {
    const firstMaskByte = mask[HP_MASK_PN_OFFSET];
    if (firstMaskByte === undefined) {
        throw new RangeError("header-protection mask is empty");
    }
    const firstByteMask = isLongHeader ? FIRST_BYTE_LOW4_MASK : FIRST_BYTE_LOW5_MASK;
    const unmaskedFirstByte = firstByte ^ (firstMaskByte & firstByteMask);

    const pnLengthActual = Math.min(pnLength, pnBytes.length);
    let packetNumber = 0n;
    for (let i = 0; i < pnLengthActual; i++) {
        const maskByte = mask[HP_MASK_FIRST_BYTE_LEN + i];
        const pnByte = pnBytes[i];
        if (maskByte === undefined || pnByte === undefined) {
            throw new RangeError(`header-protection mask / pn byte ${i} out of bounds`);
        }
        packetNumber = (packetNumber << 8n) | BigInt(pnByte ^ maskByte);
    }

    return { firstByte: unmaskedFirstByte, packetNumber };
}

/**
 * Protect a QUIC packet payload: AEAD-encrypt the payload and apply header
 * protection to the first byte + packet number (RFC 9001 §5.3, §5.4).
 *
 * @param payload         The unprotected frame payload.
 * @param packetNumber    The packet number to assign.
 * @param pnLength        Number of bytes the packet number occupies on the wire (1–4).
 * @param firstByte       The first header byte (already serialized, unprotected).
 * @param aead            AEAD algorithm.
 * @param secrets         QUIC protection secrets (key, iv, hp) for this direction + phase.
 * @param isLongHeader    Whether this is a long header.
 * @param provider        Cryptographic provider.
 * @returns The AEAD-protected payload (with tag appended) — the caller prepends
 *          the masked first byte and masked packet number to form the full packet.
 */
export function protectPayload(
    payload: Uint8Array,
    packetNumber: bigint,
    pnLength: number,
    firstByte: number,
    aead: QuicAead,
    secrets: QuicProtectionSecrets,
    isLongHeader: boolean,
    provider: CryptoProvider = crypto,
): { protectedPayload: Uint8Array; maskedFirstByte: number; maskedPacketNumber: Uint8Array } {
    // 1. AEAD-encrypt the payload with the header as AAD.
    const nonce = constructNonce(secrets.iv, packetNumber);
    // The AAD is the first byte + packet number bytes (before header protection).
    // Header protection is applied AFTER encryption, so the AAD is the raw header.
    const rawPnBytes = encodeBigInt(packetNumber, pnLength);
    const aad = concat(new Uint8Array([firstByte]), rawPnBytes);
    const protectedPayload = encryptPayload(aead, secrets.key, nonce, payload, aad, provider);

    // 2. Sample the protected payload to derive the header-protection mask.
    const sampleStart = HP_SAMPLE_OFFSET;
    const sampleEnd = sampleStart + HP_SAMPLE_LENGTH;
    if (protectedPayload.length < sampleEnd) {
        throw new RangeError(
            `Protected payload too short for header-protection sample (need ${sampleEnd}, got ${protectedPayload.length})`,
        );
    }
    const sample = protectedPayload.subarray(sampleStart, sampleEnd);
    const mask = computeHeaderProtectionMask(secrets.hp, sample, provider);

    // 3. Apply header protection to the first byte + packet number.
    const { firstByte: maskedFirstByte, packetNumberBytes: maskedPacketNumber } = applyHeaderProtection(
        firstByte,
        packetNumber,
        pnLength,
        mask,
        isLongHeader,
    );

    return { protectedPayload, maskedFirstByte, maskedPacketNumber };
}

/**
 * Unprotect a QUIC packet payload: remove header protection, then AEAD-decrypt.
 *
 * @param firstByte        The first header byte (as received, still masked).
 * @param pnBytes          The masked packet-number bytes (as received).
 * @param pnLength         Number of bytes the packet number occupies (1–4).
 * @param protectedPayload The AEAD-protected payload (with tag appended).
 * @param isLongHeader     Whether this is a long header.
 * @param aead             AEAD algorithm.
 * @param secrets          QUIC protection secrets (key, iv, hp) for this direction + phase.
 * @param provider         Cryptographic provider.
 * @returns The decrypted frame payload and the decoded packet number.
 */
export function unprotectPayload(
    firstByte: number,
    pnBytes: Uint8Array,
    pnLength: number,
    protectedPayload: Uint8Array,
    isLongHeader: boolean,
    aead: QuicAead,
    secrets: QuicProtectionSecrets,
    provider: CryptoProvider = crypto,
): { payload: Uint8Array; packetNumber: bigint } {
    // 1. Sample the protected payload to derive the header-protection mask.
    const sampleStart = HP_SAMPLE_OFFSET;
    const sampleEnd = sampleStart + HP_SAMPLE_LENGTH;
    if (protectedPayload.length < sampleEnd) {
        throw new RangeError(
            `Protected payload too short for header-protection sample (need ${sampleEnd}, got ${protectedPayload.length})`,
        );
    }
    const sample = protectedPayload.subarray(sampleStart, sampleEnd);
    const mask = computeHeaderProtectionMask(secrets.hp, sample, provider);

    // 2. Remove header protection to recover the first byte + packet number.
    const { firstByte: unmaskedFirstByte, packetNumber } = removeHeaderProtection(
        firstByte,
        pnBytes,
        pnLength,
        mask,
        isLongHeader,
    );

    // 3. AEAD-decrypt the payload with the unprotected header as AAD.
    const nonce = constructNonce(secrets.iv, packetNumber);
    const rawPnBytes = encodeBigInt(packetNumber, pnLength);
    const aad = concat(new Uint8Array([unmaskedFirstByte]), rawPnBytes);
    const payload = decryptPayload(aead, secrets.key, nonce, protectedPayload, aad, provider);

    return { payload, packetNumber };
}

void AEAD_TAG_LENGTH;

/** Encode a non-negative BigInt as a big-endian byte array of the given length. */
function encodeBigInt(value: bigint, length: number): Uint8Array {
    if (value < 0n) {
        throw new RangeError(`Cannot encode negative value as unsigned: ${value}`);
    }
    const bytes = new Uint8Array(length);
    let remaining = value;
    for (let i = length - 1; i >= 0; i--) {
        bytes[i] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    return bytes;
}
