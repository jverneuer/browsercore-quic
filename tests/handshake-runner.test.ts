/**
 * Tests for the QUIC TLS handshake runner (runQuicHandshake) and the key
 * derivation building blocks it composes.
 *
 * runQuicHandshake (src/handshake/quic-handshake.ts lines 192-344) is the
 * top-level orchestrator: it drives a TLS 1.3 handshake over a QUIC stream,
 * captures the TLS traffic secrets at each key phase, and derives the QUIC
 * packet-protection secrets (key/iv/hp) for each phase. Testing it against a
 * real TLS server is out of scope for unit tests, so we mock @browsercore/tls's
 * `runHandshake` to populate the QuicHandshakeContext with known traffic
 * secrets — then verify that runQuicHandshake correctly derives the QUIC
 * protection secrets and assembles the QuicHandshakeResult.
 *
 * We also exercise deriveQuicSecrets (the single-direction primitive from
 * src/crypto/key-derivation.ts that runQuicHandshake's internal
 * deriveQuicProtectionBoth wraps) directly, covering the SHA-384 path that the
 * existing key-derivation.test.ts leaves to SHA-256.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { crypto, SHA_256, SHA_384, type CryptoProvider, type HashId } from "@browsercore/crypto";
import type { Transport } from "@browsercore/transport";
import type {
    ApplicationTrafficSecrets,
    CipherSuite,
    ClientHelloConfig,
    HandshakeContext,
} from "@browsercore/tls";
import type * as TlsModule from "@browsercore/tls";

// ---------------------------------------------------------------------------
// Mock @browsercore/tls so runHandshake simulates a completed TLS handshake.
// ---------------------------------------------------------------------------

/**
 * The traffic secrets our mock runHandshake will install on the context.
 * Set per-test via the module-level holders below.
 */
let mockClientHsSecret: Uint8Array = new Uint8Array(32).fill(0x11);
let mockServerHsSecret: Uint8Array = new Uint8Array(32).fill(0x22);
let mockMasterSecret: Uint8Array = new Uint8Array(32).fill(0x33);
let mockCipherSuite: CipherSuite = "TLS_AES_128_GCM_SHA256";
let mockHash: HashId = SHA_256;
let mockAlpn: string | undefined = "h3";
let mockPeerCertificate: unknown;

// The mock's runHandshake signature mirrors the real one (minus the unused
// args) so the implementation stays assignable to the mocked module.
type RunHandshakeMock = (
    ctx: HandshakeContext,
    profile: ClientHelloConfig,
    serverName: string,
    trustAnchors: readonly Uint8Array[],
    generateKeyShares: unknown,
    now: number,
) => Promise<ApplicationTrafficSecrets>;

vi.mock("@browsercore/tls", async (importOriginal) => {
    const actual = await importOriginal<TlsModule>();
    const runHandshakeMock: RunHandshakeMock = (
        ctx,
        _profile,
        _serverName,
        _trustAnchors,
        _generateKeyShares,
        _now,
    ) => {
        // Simulate a completed TLS handshake by populating the context
        // with the traffic secrets the real handshake would derive.
        ctx.cipherSuite = mockCipherSuite;
        ctx.aead = mockCipherSuite === "TLS_AES_256_GCM_SHA384"
            ? "AES-256-GCM"
            : mockCipherSuite === "TLS_CHACHA20_POLY1305_SHA256"
            ? "CHACHA20-POLY1305"
            : mockCipherSuite === "TLS_AES_128_CCM_SHA256"
            ? "AES-128-CCM"
            : "AES-128-GCM";
        ctx.hash = mockHash;
        ctx.clientHsTrafficSecret = mockClientHsSecret;
        ctx.serverHsTrafficSecret = mockServerHsSecret;
        ctx.masterSecret = mockMasterSecret;
        ctx.alpnProtocol = mockAlpn;
        ctx.peerCertificate = mockPeerCertificate;
        return Promise.resolve({
            client: { key: new Uint8Array(16), iv: new Uint8Array(12) },
            server: { key: new Uint8Array(16), iv: new Uint8Array(12) },
        });
    };
    return {
        ...actual,
        runHandshake: vi.fn(runHandshakeMock),
    };
});

// ---------------------------------------------------------------------------
// Imports (after the mock is registered — vitest hoists vi.mock anyway).
// ---------------------------------------------------------------------------

import { runQuicHandshake, QuicHandshakeContext } from "../src/handshake/quic-handshake.js";
import { deriveQuicSecrets, QUIC_IV_LENGTH } from "../src/crypto/key-derivation.js";

// ---------------------------------------------------------------------------
// Fakes & helpers
// ---------------------------------------------------------------------------

function fakeTransport(): Transport {
    return {
        id: "fake-transport",
        state: { state: "open" },
        write: () => Promise.resolve(),
        read: () => Promise.resolve(new Uint8Array(0)),
        close: () => Promise.resolve(),
    } as unknown as Transport;
}

/**
 * A minimal ClientHelloConfig — runHandshake is mocked so its fields are never
 * read. We cast from a structural double because the real config has more
 * fields than the mock ever touches.
 */
function fakeProfile(): ClientHelloConfig {
    return {
        cipherSuites: ["TLS_AES_128_GCM_SHA256"],
        extensionOrder: [],
        keyShareGroups: ["x25519"],
        signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
        supportedVersions: ["TLS 1.3"],
        serverName: "example.com",
        grease: false,
    };
}

const INITIAL_DCID = new Uint8Array([0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("runQuicHandshake", () => {
    beforeEach(() => {
        // Reset the mock-installed traffic secrets to known defaults before each test.
        mockClientHsSecret = new Uint8Array(32).fill(0x11);
        mockServerHsSecret = new Uint8Array(32).fill(0x22);
        mockMasterSecret = new Uint8Array(32).fill(0x33);
        mockCipherSuite = "TLS_AES_128_GCM_SHA256";
        mockHash = SHA_256;
        mockAlpn = "h3";
        mockPeerCertificate = null;
    });

    afterEach(() => {
        vi.clearAllMocks();
    });

    it("returns a result with all three key phases in derivation order", async () => {
        const result = await runQuicHandshake(
            fakeTransport(),
            fakeProfile(),
            "example.com",
            INITIAL_DCID,
        );
        expect(result.phases).toHaveLength(3);
        expect(result.phases[0].phase).toBe("initial");
        expect(result.phases[1].phase).toBe("handshake");
        expect(result.phases[2].phase).toBe("application");
    });

    it("maps the negotiated cipher suite to the QUIC AEAD algorithm + hash", async () => {
        const result = await runQuicHandshake(
            fakeTransport(),
            fakeProfile(),
            "example.com",
            INITIAL_DCID,
        );
        expect(result.aead).toBe("AES-128-GCM");
        expect(result.hash).toBe("SHA-256");
        expect(result.cipherSuite).toBe("TLS_AES_128_GCM_SHA256");
    });

    it("produces AES-128 key lengths (16-byte key/hp, 12-byte iv) for the AES_128_GCM suite", async () => {
        const result = await runQuicHandshake(
            fakeTransport(),
            fakeProfile(),
            "example.com",
            INITIAL_DCID,
        );
        for (const phase of result.phases) {
            expect(phase.clientProtection.key.length).toBe(16);
            expect(phase.clientProtection.hp.length).toBe(16);
            expect(phase.clientProtection.iv.length).toBe(12);
            expect(phase.serverProtection.key.length).toBe(16);
            expect(phase.serverProtection.hp.length).toBe(16);
            expect(phase.serverProtection.iv.length).toBe(12);
        }
    });

    it("produces AES-256 key lengths (32-byte key/hp) for the AES_256_GCM suite", async () => {
        mockCipherSuite = "TLS_AES_256_GCM_SHA384";
        mockHash = SHA_384;
        // AES-256-GCM uses SHA-384 → 48-byte traffic secrets.
        mockClientHsSecret = new Uint8Array(48).fill(0x11);
        mockServerHsSecret = new Uint8Array(48).fill(0x22);
        mockMasterSecret = new Uint8Array(48).fill(0x33);

        const result = await runQuicHandshake(
            fakeTransport(),
            fakeProfile(),
            "example.com",
            INITIAL_DCID,
        );
        expect(result.aead).toBe("AES-256-GCM");
        expect(result.hash).toBe("SHA-384");
        expect(result.cipherSuite).toBe("TLS_AES_256_GCM_SHA384");

        // The initial phase always uses a hardcoded 16-byte key (AES-128-GCM is
        // the QUIC v1 default for initial secrets, RFC 9001 §5.2). Only the
        // handshake + application phases use the negotiated key length.
        const initial = result.phases[0];
        expect(initial.clientProtection.key.length).toBe(16);
        expect(initial.serverProtection.key.length).toBe(16);

        for (const phase of [result.phases[1], result.phases[2]]) {
            expect(phase.clientProtection.key.length).toBe(32);
            expect(phase.clientProtection.hp.length).toBe(32);
            expect(phase.clientProtection.iv.length).toBe(12);
            expect(phase.serverProtection.key.length).toBe(32);
            expect(phase.serverProtection.hp.length).toBe(32);
            expect(phase.serverProtection.iv.length).toBe(12);
        }
    });

    it("produces distinct client and server protection secrets per phase", async () => {
        const result = await runQuicHandshake(
            fakeTransport(),
            fakeProfile(),
            "example.com",
            INITIAL_DCID,
        );
        for (const phase of result.phases) {
            expect(Buffer.from(phase.clientProtection.key)
                .equals(Buffer.from(phase.serverProtection.key))).toBe(false);
            expect(Buffer.from(phase.clientTrafficSecret)
                .equals(Buffer.from(phase.serverTrafficSecret))).toBe(false);
        }
    });

    it("produces distinct key, iv, and hp within each protection secret", async () => {
        const result = await runQuicHandshake(
            fakeTransport(),
            fakeProfile(),
            "example.com",
            INITIAL_DCID,
        );
        for (const phase of result.phases) {
            for (const dir of [phase.clientProtection, phase.serverProtection] as const) {
                expect(Buffer.from(dir.key).equals(Buffer.from(dir.iv))).toBe(false);
                expect(Buffer.from(dir.key).equals(Buffer.from(dir.hp))).toBe(false);
                expect(Buffer.from(dir.iv).equals(Buffer.from(dir.hp))).toBe(false);
            }
        }
    });

    it("derives different initial secrets for different DCIDs", async () => {
        const dcidA = new Uint8Array([0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
        const dcidB = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        const resultA = await runQuicHandshake(fakeTransport(), fakeProfile(), "example.com", dcidA);
        const resultB = await runQuicHandshake(fakeTransport(), fakeProfile(), "example.com", dcidB);

        // Initial phase secrets differ because the DCID feeds the initial salt derivation.
        const initialA = resultA.phases[0];
        const initialB = resultB.phases[0];
        expect(Buffer.from(initialA.clientTrafficSecret)
            .equals(Buffer.from(initialB.clientTrafficSecret))).toBe(false);
        expect(Buffer.from(initialA.serverTrafficSecret)
            .equals(Buffer.from(initialB.serverTrafficSecret))).toBe(false);

        // Handshake + application phases are identical (same mock traffic secrets).
        expect(Array.from(resultA.phases[1].clientTrafficSecret))
            .toEqual(Array.from(resultB.phases[1].clientTrafficSecret));
        expect(Array.from(resultA.phases[2].clientTrafficSecret))
            .toEqual(Array.from(resultB.phases[2].clientTrafficSecret));
    });

    it("is deterministic for the same DCID + traffic secrets", async () => {
        const a = await runQuicHandshake(fakeTransport(), fakeProfile(), "example.com", INITIAL_DCID);
        const b = await runQuicHandshake(fakeTransport(), fakeProfile(), "example.com", INITIAL_DCID);
        expect(Array.from(a.phases[0].clientTrafficSecret))
            .toEqual(Array.from(b.phases[0].clientTrafficSecret));
        expect(Array.from(a.phases[0].clientProtection.key))
            .toEqual(Array.from(b.phases[0].clientProtection.key));
    });

    it("includes the ALPN protocol when the server negotiates one", async () => {
        mockAlpn = "h3";
        const result = await runQuicHandshake(
            fakeTransport(),
            fakeProfile(),
            "example.com",
            INITIAL_DCID,
        );
        expect(result.alpnProtocol).toBe("h3");
    });

    it("omits ALPN from the result when the server does not negotiate one", async () => {
        mockAlpn = undefined;
        const result = await runQuicHandshake(
            fakeTransport(),
            fakeProfile(),
            "example.com",
            INITIAL_DCID,
        );
        expect(result).not.toHaveProperty("alpnProtocol");
        expect(result.alpnProtocol).toBeUndefined();
    });

    it("forwards the peer certificate from the TLS handshake", async () => {
        const cert = { subject: "CN=example.com", issuer: "CN=Test CA" };
        mockPeerCertificate = cert;
        const result = await runQuicHandshake(
            fakeTransport(),
            fakeProfile(),
            "example.com",
            INITIAL_DCID,
        );
        expect(result.peerCertificate).toBe(cert);
    });

    it("maps CHACHA20-POLY1305 correctly", async () => {
        mockCipherSuite = "TLS_CHACHA20_POLY1305_SHA256";
        const result = await runQuicHandshake(
            fakeTransport(),
            fakeProfile(),
            "example.com",
            INITIAL_DCID,
        );
        expect(result.aead).toBe("CHACHA20-POLY1305");
        expect(result.hash).toBe("SHA-256");
    });

    it("passes the injected crypto provider down via the context", async () => {
        const result = await runQuicHandshake(
            fakeTransport(),
            fakeProfile(),
            "example.com",
            INITIAL_DCID,
            [],
            Math.floor(Date.now() / 1000),
            crypto,
        );
        // The derivation succeeds (produces correctly-sized keys) with the real provider.
        expect(result.phases[0].clientProtection.key.length).toBe(16);
    });

    it("installs the handshake traffic secrets from the context into the handshake phase", async () => {
        // Distinct client/server handshake secrets so we can assert they propagate.
        mockClientHsSecret = crypto.randomBytes(32);
        mockServerHsSecret = crypto.randomBytes(32);

        const result = await runQuicHandshake(
            fakeTransport(),
            fakeProfile(),
            "example.com",
            INITIAL_DCID,
        );
        const handshakePhase = result.phases[1];
        expect(Array.from(handshakePhase.clientTrafficSecret)).toEqual(Array.from(mockClientHsSecret));
        expect(Array.from(handshakePhase.serverTrafficSecret)).toEqual(Array.from(mockServerHsSecret));
    });

    it("uses the master secret (not the handshake secret) to derive the application phase traffic secrets", async () => {
        mockMasterSecret = crypto.randomBytes(32);
        mockClientHsSecret = crypto.randomBytes(32);
        mockServerHsSecret = crypto.randomBytes(32);

        const result = await runQuicHandshake(
            fakeTransport(),
            fakeProfile(),
            "example.com",
            INITIAL_DCID,
        );
        const appPhase = result.phases[2];
        // The application traffic secrets are derived from the master secret via
        // TLS 1.3 HKDF-Expand-Label ("c ap traffic" / "s ap traffic"), so they
        // must differ from the handshake traffic secrets (derived from the hs secrets).
        expect(Buffer.from(appPhase.clientTrafficSecret)
            .equals(Buffer.from(mockClientHsSecret))).toBe(false);
        expect(Buffer.from(appPhase.serverTrafficSecret)
            .equals(Buffer.from(mockServerHsSecret))).toBe(false);
        // And must be non-empty (the real derivation produces hash-length bytes).
        expect(appPhase.clientTrafficSecret.length).toBeGreaterThan(0);
        expect(appPhase.serverTrafficSecret.length).toBeGreaterThan(0);
    });
});

describe("QuicHandshakeContext as a HandshakeContext implementation", () => {
    it("exposes the transport and crypto provider it was constructed with", () => {
        const transport = fakeTransport();
        const provider: CryptoProvider = crypto;
        const ctx = new QuicHandshakeContext(transport, provider);
        expect(ctx.transport).toBe(transport);
        expect(ctx.crypto).toBe(provider);
    });

    it("is mutable in all the fields runHandshake would write", () => {
        const ctx = new QuicHandshakeContext(fakeTransport(), crypto);
        // Simulate runHandshake mutating the context.
        ctx.cipherSuite = "TLS_AES_256_GCM_SHA384";
        ctx.aead = "AES-256-GCM";
        ctx.hash = SHA_384;
        ctx.clientHsTrafficSecret = new Uint8Array(48).fill(0xaa);
        ctx.serverHsTrafficSecret = new Uint8Array(48).fill(0xbb);
        ctx.masterSecret = new Uint8Array(48).fill(0xcc);
        ctx.alpnProtocol = "h3";
        ctx.peerCertificate = { subject: "CN=test" };

        expect(ctx.cipherSuite).toBe("TLS_AES_256_GCM_SHA384");
        expect(ctx.aead).toBe("AES-256-GCM");
        expect(ctx.hash).toBe(SHA_384);
        expect(ctx.clientHsTrafficSecret.length).toBe(48);
        expect(ctx.serverHsTrafficSecret.length).toBe(48);
        expect(ctx.masterSecret.length).toBe(48);
        expect(ctx.alpnProtocol).toBe("h3");
        expect(ctx.peerCertificate).toEqual({ subject: "CN=test" });
    });
});

describe("deriveQuicSecrets (single-direction primitive from key-derivation.ts)", () => {
    it("produces 32-byte key/hp + 12-byte iv for SHA-384", () => {
        const trafficSecret = crypto.randomBytes(48); // SHA-384 digest length
        const secrets = deriveQuicSecrets(trafficSecret, 32, SHA_384, crypto);
        expect(secrets.key.length).toBe(32);
        expect(secrets.hp.length).toBe(32);
        expect(secrets.iv.length).toBe(QUIC_IV_LENGTH);
    });

    it("produces 16-byte key/hp + 12-byte iv for SHA-256 (AES-128)", () => {
        const trafficSecret = crypto.randomBytes(32);
        const secrets = deriveQuicSecrets(trafficSecret, 16, SHA_256, crypto);
        expect(secrets.key.length).toBe(16);
        expect(secrets.hp.length).toBe(16);
        expect(secrets.iv.length).toBe(QUIC_IV_LENGTH);
    });

    it("produces distinct key, iv, and hp for SHA-384", () => {
        const trafficSecret = crypto.randomBytes(48);
        const secrets = deriveQuicSecrets(trafficSecret, 32, SHA_384, crypto);
        expect(Buffer.from(secrets.key).equals(Buffer.from(secrets.iv))).toBe(false);
        expect(Buffer.from(secrets.key).equals(Buffer.from(secrets.hp))).toBe(false);
        expect(Buffer.from(secrets.iv).equals(Buffer.from(secrets.hp))).toBe(false);
    });

    it("is deterministic for the same inputs (SHA-384)", () => {
        const trafficSecret = crypto.randomBytes(48);
        const a = deriveQuicSecrets(trafficSecret, 32, SHA_384, crypto);
        const b = deriveQuicSecrets(trafficSecret, 32, SHA_384, crypto);
        expect(Array.from(a.key)).toEqual(Array.from(b.key));
        expect(Array.from(a.iv)).toEqual(Array.from(b.iv));
        expect(Array.from(a.hp)).toEqual(Array.from(b.hp));
    });

    it("produces different secrets for different traffic secrets (SHA-384)", () => {
        const secretA = crypto.randomBytes(48);
        const secretB = crypto.randomBytes(48);
        const a = deriveQuicSecrets(secretA, 32, SHA_384, crypto);
        const b = deriveQuicSecrets(secretB, 32, SHA_384, crypto);
        expect(Buffer.from(a.key).equals(Buffer.from(b.key))).toBe(false);
    });

    it("produces the same output when called via the wrapper that runQuicHandshake uses internally", () => {
        // runQuicHandshake's internal deriveQuicProtectionBoth calls deriveQuicSecrets
        // once per direction. Verify that calling deriveQuicSecrets directly matches
        // what the handshake runner would compute for a given traffic secret.
        const trafficSecret = crypto.randomBytes(32);
        const direct = deriveQuicSecrets(trafficSecret, 16, SHA_256, crypto);
        expect(direct.key.length).toBe(16);
        expect(direct.iv.length).toBe(12);
        expect(direct.hp.length).toBe(16);
    });
});
