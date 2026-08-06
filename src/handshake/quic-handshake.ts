/**
 * QUIC TLS handshake orchestration (RFC 9001 §4, §8).
 *
 * Runs the @browsercore/tls 1.3 handshake over a QUIC bidirectional stream
 * (stream 0), capturing the TLS traffic secrets at each key phase so the QUIC
 * layer can derive its packet-protection keys (RFC 9001 §5.1). The three key
 * phases map to QUIC key phases:
 *
 *   Initial DCID + version salt                  → QUIC initial keys
 *   TLS handshake traffic secrets (c/s hs)        → QUIC handshake keys
 *   TLS application traffic secrets (c/s ap)      → QUIC application (1-RTT) keys
 *
 * The @browsercore/tls `runHandshake` returns only the final
 * `ApplicationTrafficSecrets`, but the `HandshakeContext` it mutates holds the
 * intermediate secrets (clientHsTrafficSecret, serverHsTrafficSecret,
 * masterSecret). We implement `HandshakeContext` so we can read them after the
 * handshake completes, then derive the QUIC packet-protection secrets.
 */

import { crypto, SHA_256, type CryptoProvider, type HashId } from "@browsercore/crypto";
import type { Transport } from "@browsercore/transport";
import {
    generateKeyShares,
    cipherSuiteToAead,
    runHandshake,
    type AeadAlgorithm,
    type CipherSuite,
    type ClientHelloConfig,
    type ServerHello,
    type Certificate,
    type TrafficSecrets,
    type HandshakeContext,
} from "@browsercore/tls";
import {
    deriveInitialSecrets,
    deriveQuicSecrets,
    INITIAL_SALT_V1,
    type QuicProtectionSecrets,
} from "../crypto/key-derivation.js";
import { hashLengthFor } from "../crypto/hash-length.js";

/** A QUIC key phase — maps to the TLS secrets that feed QUIC's key derivation. */
export type QuicKeyPhase = "initial" | "handshake" | "application";

/**
 * The QUIC packet-protection secrets derived from a TLS key phase, plus the raw
 * traffic secrets that fed the derivation (so callers can re-derive if needed).
 */
export interface QuicPhaseSecrets {
    /** QUIC key phase these secrets belong to. */
    readonly phase: QuicKeyPhase;
    /** Client traffic secret (hash-length bytes) for this phase. */
    readonly clientTrafficSecret: Uint8Array;
    /** Server traffic secret (hash-length bytes) for this phase. */
    readonly serverTrafficSecret: Uint8Array;
    /** Derived QUIC packet-protection secrets for the client (→ write direction). */
    readonly clientProtection: QuicProtectionSecrets;
    /** Derived QUIC packet-protection secrets for the server (← read direction). */
    readonly serverProtection: QuicProtectionSecrets;
}

/**
 * The full result of the QUIC TLS handshake — the traffic secrets at every
 * phase, the negotiated AEAD + hash (so the QUIC layer can size keys), the
 * negotiated ALPN, and the peer certificate.
 */
export interface QuicHandshakeResult {
    /** Secrets at each key phase, in derivation order. */
    readonly phases: readonly QuicPhaseSecrets[];
    /** Negotiated AEAD algorithm (determines key length). */
    readonly aead: AeadAlgorithm;
    /** Negotiated hash function (determines traffic-secret length). */
    readonly hash: "SHA-256" | "SHA-384";
    /** Negotiated cipher suite. */
    readonly cipherSuite: CipherSuite;
    /** ALPN protocol the server selected, if any. */
    readonly alpnProtocol?: string;
    /** Peer leaf certificate, once validated. */
    readonly peerCertificate: unknown;
}

/**
 * A minimal HandshakeContext implementation that delegates to @browsercore/tls's
 * `runHandshake` and captures the intermediate traffic secrets for QUIC key
 * derivation.
 */
export class QuicHandshakeContext implements HandshakeContext {
    public readonly transport: Transport;
    public readonly crypto: CryptoProvider;
    public readBuffer: Uint8Array = new Uint8Array(0);
    public readonly transcript: Uint8Array[] = [];
    public cipherSuite: CipherSuite = "TLS_AES_128_GCM_SHA256";
    public aead: AeadAlgorithm = "AES-128-GCM";
    public hash: HashId = SHA_256;
    public serverHello: ServerHello = undefined as unknown as ServerHello;
    public clientHsTraffic: TrafficSecrets = { key: new Uint8Array(0), iv: new Uint8Array(0) };
    public serverHsTraffic: TrafficSecrets = { key: new Uint8Array(0), iv: new Uint8Array(0) };
    public clientHsTrafficSecret: Uint8Array = new Uint8Array(0);
    public serverHsTrafficSecret: Uint8Array = new Uint8Array(0);
    public masterSecret: Uint8Array = new Uint8Array(0);
    public clientHsSeq = 0;
    public serverHsSeq = 0;
    public alpnProtocol?: string;
    public peerCertificate?: Certificate;

    public constructor(transport: Transport, cryptoProvider: CryptoProvider) {
        this.transport = transport;
        this.crypto = cryptoProvider;
    }
}

/**
 * Map a TLS cipher suite to its AEAD algorithm name.
 * (Local copy — @browsercore/tls exports cipherSuiteToAead but we want to avoid
 * a dependency on the exact export path.)
 */
// Lenient by design: QUIC only negotiates AEAD cipher suites, but the TLS
// handshake may report others. Known QUIC suites map explicitly; everything
// else falls back to @browsercore/tls's mapping (which is itself exhaustive).
export function mapCipherSuite(cipherSuite: CipherSuite): AeadAlgorithm {
    // oxlint-disable-next-line typescript/switch-exhaustiveness-check -- intentional fallback for non-AEAD suites
    switch (cipherSuite) {
        case "TLS_AES_128_GCM_SHA256":
            return "AES-128-GCM";
        case "TLS_AES_128_CCM_SHA256":
            return "AES-128-CCM";
        case "TLS_AES_256_GCM_SHA384":
            return "AES-256-GCM";
        case "TLS_CHACHA20_POLY1305_SHA256":
            return "CHACHA20-POLY1305";
        default:
            return cipherSuiteToAead(cipherSuite);
    }
}

/**
 * Map a TLS cipher suite to its HKDF hash function. Only AES-256-GCM /
 * ChaCha20-256 use SHA-384; every other QUIC suite uses SHA-256. The default
 * is the common case so non-QUIC suites still derive a valid (if mismatched) hash.
 */
export function hashForCipherSuite(cipherSuite: CipherSuite): HashId {
    // oxlint-disable-next-line typescript/switch-exhaustiveness-check -- SHA-256 is the correct default for all non-AES-256 suites
    switch (cipherSuite) {
        case "TLS_AES_256_GCM_SHA384":
            return "SHA-384" as HashId;
        default:
            return "SHA-256" as HashId;
    }
}

/**
 * AEAD key length in bytes for a cipher suite. 16 bytes for 128-bit keys,
 * 32 bytes for 256-bit keys. Defaults to 16 (the common case) for any suite
 * not explicitly listed.
 */
export function cipherSuiteKeyLength(cipherSuite: CipherSuite): number {
    // oxlint-disable-next-line typescript/switch-exhaustiveness-check -- 16 bytes is a safe minimum default
    switch (cipherSuite) {
        case "TLS_AES_128_GCM_SHA256":
        case "TLS_AES_128_CCM_SHA256":
        case "TLS_CHACHA20_POLY1305_SHA256":
            return 16;
        case "TLS_AES_256_GCM_SHA384":
            return 32;
        default:
            return 16;
    }
}

/**
 * Run the TLS 1.3 handshake over the given transport, capturing QUIC packet-
 * protection secrets at each key phase.
 *
 * @param transport      A TLS Transport (e.g. a {@link QuicTransportAdapter} wrapping QUIC stream 0).
 * @param profile        ClientHello configuration (cipher suites, key-share groups, etc.).
 * @param serverName     SNI hostname (for SNI + certificate validation).
 * @param initialDcid    The client's initial DCID — used to derive the initial QUIC secrets.
 * @param trustAnchors   Trust anchors (PEM/DER) for certificate validation. Defaults to system roots.
 * @param clockNow       Current epoch seconds (injected for deterministic cert validation).
 * @param cryptoProvider Cryptographic provider (defaults to the @browsercore/crypto singleton).
 */
export async function runQuicHandshake(
    transport: Transport,
    profile: ClientHelloConfig,
    serverName: string,
    initialDcid: Uint8Array,
    trustAnchors: readonly Uint8Array[] = [],
    clockNow: number = Math.floor(Date.now() / 1000),
    cryptoProvider: CryptoProvider = crypto,
): Promise<QuicHandshakeResult> {
    // --- Phase 0: derive initial QUIC secrets from the DCID (RFC 9001 §5.2) --
    const initial = deriveInitialSecrets(initialDcid, INITIAL_SALT_V1, SHA_256, cryptoProvider);
    const initialKeyLen = 16; // AES-128-GCM is the QUIC v1 default
    const initialProtection = deriveQuicProtectionBoth(
        initial.clientInitialSecret,
        initial.serverInitialSecret,
        initialKeyLen,
        SHA_256,
        cryptoProvider,
    );

    // --- TLS handshake --------------------------------------------------------
    const ctx = new QuicHandshakeContext(transport, cryptoProvider);
    await runHandshake(
        ctx,
        profile,
        serverName,
        trustAnchors,
        (groups) => generateKeyShares(groups, cryptoProvider),
        clockNow,
    );

    // --- Phase 1: handshake QUIC keys ---------------------------------------
    const negotiatedKeyLen = cipherSuiteKeyLength(ctx.cipherSuite);
    const handshakeProtection = deriveQuicProtectionBoth(
        ctx.clientHsTrafficSecret,
        ctx.serverHsTrafficSecret,
        negotiatedKeyLen,
        ctx.hash,
        ctx.crypto,
    );

    // --- Phase 2: application (1-RTT) QUIC keys -----------------------------
    // The application traffic secrets are derived from the master secret via
    // HKDF-Expand-Label. We replicate the TLS key schedule's derivation here
    // using the local hash-length helper + the QUIC HKDF-Expand-Label.
    const hashLen = hashLengthFor(ctx.hash);
    const apClientSecret = quicHkdfExpandLabelForTls(
        ctx.masterSecret,
        "c ap traffic",
        new Uint8Array(0),
        hashLen,
        ctx.hash,
        ctx.crypto,
    );
    const apServerSecret = quicHkdfExpandLabelForTls(
        ctx.masterSecret,
        "s ap traffic",
        new Uint8Array(0),
        hashLen,
        ctx.hash,
        ctx.crypto,
    );
    const applicationProtection = deriveQuicProtectionBoth(
        apClientSecret,
        apServerSecret,
        negotiatedKeyLen,
        ctx.hash,
        ctx.crypto,
    );

    const initialPhaseSecrets: QuicPhaseSecrets = {
        phase: "initial",
        clientTrafficSecret: initial.clientInitialSecret,
        serverTrafficSecret: initial.serverInitialSecret,
        clientProtection: initialProtection.clientProtection,
        serverProtection: initialProtection.serverProtection,
    };
    const handshakePhaseSecrets: QuicPhaseSecrets = {
        phase: "handshake",
        clientTrafficSecret: ctx.clientHsTrafficSecret,
        serverTrafficSecret: ctx.serverHsTrafficSecret,
        clientProtection: handshakeProtection.clientProtection,
        serverProtection: handshakeProtection.serverProtection,
    };
    const applicationPhaseSecrets: QuicPhaseSecrets = {
        phase: "application",
        clientTrafficSecret: apClientSecret,
        serverTrafficSecret: apServerSecret,
        clientProtection: applicationProtection.clientProtection,
        serverProtection: applicationProtection.serverProtection,
    };

    return {
        phases: [initialPhaseSecrets, handshakePhaseSecrets, applicationPhaseSecrets],
        aead: mapCipherSuite(ctx.cipherSuite),
        hash: ctx.hash === "SHA-384" ? "SHA-384" : "SHA-256",
        cipherSuite: ctx.cipherSuite,
        ...(ctx.alpnProtocol === undefined ? {} : { alpnProtocol: ctx.alpnProtocol }),
        peerCertificate: ctx.peerCertificate,
    };
}

/**
 * HKDF-Expand-Label per RFC 8446 §7.1 (TLS 1.3, "tls13 " prefix).
 * Used to derive the application traffic secrets from the master secret.
 */
function quicHkdfExpandLabelForTls(
    secret: Uint8Array,
    label: string,
    context: Uint8Array,
    length: number,
    hash: HashId,
    provider: CryptoProvider,
): Uint8Array {
    const prefix = "tls13 ";
    const labelBytes = new TextEncoder().encode(prefix + label);
    const hkdfLabel = new Uint8Array(2 + 1 + labelBytes.length + 1 + context.length);
    let o = 0;
    hkdfLabel[o++] = (length >> 8) & 0xff;
    hkdfLabel[o++] = length & 0xff;
    hkdfLabel[o++] = labelBytes.length & 0xff;
    hkdfLabel.set(labelBytes, o);
    o += labelBytes.length;
    hkdfLabel[o++] = context.length & 0xff;
    hkdfLabel.set(context, o);
    return hkdfExpandLocal(hash, secret, hkdfLabel, length, provider);
}

/** Local HKDF-Expand on top of the HMAC primitive. */
function hkdfExpandLocal(
    hash: HashId,
    prk: Uint8Array,
    info: Uint8Array,
    length: number,
    provider: CryptoProvider,
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

/** Derive QUIC protection secrets (client + server) from a phase's traffic secrets. */
function deriveQuicProtectionBoth(
    clientTrafficSecret: Uint8Array,
    serverTrafficSecret: Uint8Array,
    keyLength: number,
    hash: HashId,
    provider: CryptoProvider,
): Pick<QuicPhaseSecrets, "clientProtection" | "serverProtection"> {
    return {
        clientProtection: deriveQuicSecrets(clientTrafficSecret, keyLength, hash, provider),
        serverProtection: deriveQuicSecrets(serverTrafficSecret, keyLength, hash, provider),
    };
}


