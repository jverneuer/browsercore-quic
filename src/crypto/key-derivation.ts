/**
 * QUIC key derivation (RFC 9001 §5).
 *
 * QUIC derives its packet-protection keys from TLS traffic secrets. The
 * derivation uses HKDF-Expand-Label with a "quic " prefix (distinct from
 * TLS 1.3's "tls13 " prefix) and a version-specific salt for the initial
 * secrets.
 *
 * Key schedule (RFC 9001 §5.1, §5.2):
 *   initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
 *   client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
 *   server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
 *
 * For each subsequent TLS traffic secret (handshake, application), QUIC derives:
 *   quic_key = HKDF-Expand-Label(Secret, "quic key", "", key_length)
 *   quic_iv  = HKDF-Expand-Label(Secret, "quic iv", "", 12)
 *   quic_hp  = HKDF-Expand-Label(Secret, "quic hp", "", key_length)
 *
 * All HKDF operations delegate to @browsercore/crypto — this module owns only
 * the label strings and the HKDF-Expand-Label wire format per RFC 9001 §5.1.
 */

import { crypto, SHA_256, type CryptoProvider, type HashId } from "@browsercore/crypto";
import { hashLengthFor } from "./hash-length.js";

/**
 * QUIC HKDF-Expand-Label (RFC 9001 §5.1).
 *
 * Differs from TLS 1.3's HKDF-Expand-Label (RFC 8446 §7.1) only in the label
 * prefix: QUIC uses "quic " (5 bytes) instead of "tls13 " (6 bytes). The
 * HkdfLabel struct is otherwise identical:
 *
 *   struct {
 *       uint16 length = Length;
 *       opaque label<7..255> = "quic " + Label;
 *       opaque context<0..255> = Context;
 *   } HkdfLabel;
 */
export function quicHkdfExpandLabel(
    secret: Uint8Array,
    label: string,
    context: Uint8Array,
    length: number,
    hash: HashId = SHA_256,
    provider: CryptoProvider = crypto,
): Uint8Array {
    const prefix = "quic ";
    const labelBytes = new TextEncoder().encode(prefix + label);
    // HkdfLabel: uint16 length || uint8 label_len || label || uint8 ctx_len || context.
    const hkdfLabel = new Uint8Array(2 + 1 + labelBytes.length + 1 + context.length);
    let o = 0;
    hkdfLabel[o++] = (length >> 8) & 0xff;
    hkdfLabel[o++] = length & 0xff;
    hkdfLabel[o++] = labelBytes.length & 0xff;
    hkdfLabel.set(labelBytes, o);
    o += labelBytes.length;
    hkdfLabel[o++] = context.length & 0xff;
    hkdfLabel.set(context, o);
    return hkdfExpand(hash, secret, hkdfLabel, length, provider);
}

/**
 * HKDF-Expand(PRK, info, length) per RFC 5869 §2.3, implemented on top of HMAC
 * because @browsercore/crypto exposes only the combined extract+expand helper.
 * The TLS key-schedule needs extract and expand independently; QUIC's key
 * derivation likewise needs expand standalone (the extract step is done with
 * the version-specific salt + DCID by the caller).
 */
function hkdfExpand(
    hash: HashId,
    prk: Uint8Array,
    info: Uint8Array,
    length: number,
    provider: CryptoProvider = crypto,
): Uint8Array {
    const hashLen = hashLengthFor(hash);
    const n = Math.ceil(length / hashLen);
    if (n > 255) {
        throw new RangeError(`HKDF-Expand length ${length} exceeds maximum for hash (255 * ${hashLen})`);
    }
    const okm = new Uint8Array(n * hashLen);
    let t: Uint8Array = new Uint8Array(0);
    for (let i = 1; i <= n; i++) {
        const block = new Uint8Array(t.length + info.length + 1);
        block.set(t, 0);
        block.set(info, t.length);
        block[block.length - 1] = i;
        t = provider.hmac(hash, prk, block);
        okm.set(t, (i - 1) * hashLen);
    }
    return okm.subarray(0, length);
}

/**
 * Derive a single direction's QUIC packet-protection secrets (key, iv, hp)
 * from a TLS traffic secret (RFC 9001 §5.1).
 *
 * @param trafficSecret TLS traffic secret (hash-length bytes).
 * @param keyLength     AEAD key length in bytes (16 for AES-128, 32 for AES-256 / ChaCha20).
 * @param hash          Hash function matching the TLS cipher suite.
 */
export function deriveQuicSecrets(
    trafficSecret: Uint8Array,
    keyLength: number,
    hash: HashId = SHA_256,
    provider: CryptoProvider = crypto,
): QuicProtectionSecrets {
    const key = quicHkdfExpandLabel(trafficSecret, "key", new Uint8Array(0), keyLength, hash, provider);
    const iv = quicHkdfExpandLabel(trafficSecret, "iv", new Uint8Array(0), QUIC_IV_LENGTH, hash, provider);
    const hp = quicHkdfExpandLabel(trafficSecret, "hp", new Uint8Array(0), keyLength, hash, provider);
    return { key, iv, hp };
}

/**
 * Derive the initial QUIC secrets (client + server) from the initial DCID and
 * the QUIC version's initial salt (RFC 9001 §5.2).
 *
 *   initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
 *   client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", Hash.length)
 *   server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", Hash.length)
 *
 * @param initialDcid   The client's initial destination connection id (the one on the first Initial packet).
 * @param initialSalt   Version-specific initial salt (see {@link INITIAL_SALT_V1}).
 * @param hash          Hash function for the derivation (SHA-256 for all current cipher suites).
 */
export function deriveInitialSecrets(
    initialDcid: Uint8Array,
    initialSalt: Uint8Array,
    hash: HashId = SHA_256,
    provider: CryptoProvider = crypto,
): InitialSecrets {
    const initialSecret = provider.hmac(hash, initialSalt, initialDcid);
    const hashLen = hashLengthFor(hash);
    const clientSecret = quicHkdfExpandLabel(initialSecret, "client in", new Uint8Array(0), hashLen, hash, provider);
    const serverSecret = quicHkdfExpandLabel(initialSecret, "server in", new Uint8Array(0), hashLen, hash, provider);
    return { clientInitialSecret: clientSecret, serverInitialSecret: serverSecret };
}

/** QUIC packet-protection secrets for one direction at one key phase. */
export interface QuicProtectionSecrets {
    /** AEAD key for payload encryption/decryption. */
    readonly key: Uint8Array;
    /** AEAD IV (12 bytes) — XOR'd with the packet number to form the nonce. */
    readonly iv: Uint8Array;
    /** Header-protection key — AES-ECB-encrypted with the sample to produce the mask. */
    readonly hp: Uint8Array;
}

/** Client + server initial traffic secrets derived from the initial DCID. */
export interface InitialSecrets {
    /** Client's initial traffic secret (used to protect client Initial packets). */
    readonly clientInitialSecret: Uint8Array;
    /** Server's initial traffic secret (used to protect server Initial packets). */
    readonly serverInitialSecret: Uint8Array;
}

/**
 * The IV length QUIC uses for all AEAD algorithms (RFC 9000 §12.3, RFC 9001 §5.3).
 * QUIC constructs the per-packet nonce by XORing the (zero-padded, big-endian)
 * packet number into this static IV.
 */
export const QUIC_IV_LENGTH = 12 as const;

/**
 * Initial salt for QUIC version 1 (RFC 9001 §5.2, RFC 9000 §32.2.1).
 * Used to derive the initial traffic secrets from the initial DCID.
 */
export const INITIAL_SALT_V1 = new Uint8Array([
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
]);
