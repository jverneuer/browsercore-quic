/**
 * Tests for TLS handshake engine injection (replaceability audit 2026-11-16,
 * remediation item #2 — "THE no-hard-wires fix").
 *
 * quic consumes the contracts `TlsHandshakeEngine` interface and never imports
 * @browsercore/tls statically. These tests prove the injection seam end to end:
 *
 * 1. INJECTED PATH: a fake `TlsHandshakeEngine` (the http3 fake-quic pattern —
 *    a local structural implementation satisfying the consumer's contract)
 *    drives a full `connectQuic` handshake while @browsercore/tls is
 *    module-mocked. The mock factory throwing proves the deprecated dynamic
 *    fallback import is NEVER taken when an engine is injected.
 * 2. FALLBACK PATH: the same setup without an engine proves the dynamic
 *    fallback IS taken (mock factory invoked) — 0.2.x back-compat — and that
 *    the mock genuinely intercepts (the injected-path assertions are not
 *    vacuously passing).
 * 3. DETERMINISTIC CLOCK: the handshake's certificate time flows from the
 *    resolved canonical Clock (`QuicOptions.clock`, then `platform.time` —
 *    Time ≡ Clock) into `engine.runHandshake`'s `now` argument, never from
 *    `Date.now()` directly.
 * 4. CANONICAL CLOCK SURFACE: the migrated `systemClock` (0.2.7) implements
 *    the FULL contracts Clock, not just the `now()` subset quic calls.
 */

import { describe, expect, it, vi } from "vitest";
import { createFakeDatagramPair, PEER_ADDR, testCryptoProvider, testEventProvider } from "./fake-transport.js";
import type {
    ClientHelloConfig,
    Clock,
    NamedGroup,
    Platform,
    TlsHandshakeContext,
    TlsHandshakeEngine,
    TimerHandle,
} from "@browsercore/contracts";
import type { Transport } from "@browsercore/transport";
import { connectQuic } from "../src/connection.js";
import { EMPTY_CONNECTION_ID, systemClock, type QuicConnection } from "../src/types.js";
import { runQuicHandshake, mapCipherSuite } from "../src/handshake/quic-handshake.js";

// ---------------------------------------------------------------------------
// Mock @browsercore/tls — the module the deprecated dynamic fallback imports.
// ---------------------------------------------------------------------------

/**
 * Counts how often the mocked @browsercore/tls module was dynamically
 * imported. Every access to a mocked function throws so that any fallback use
 * on the injected path fails loudly (and visibly in the record below).
 */
const tlsImport = vi.hoisted(() => ({ loads: 0 }));

vi.mock("@browsercore/tls", () => {
    tlsImport.loads += 1;
    const fail = (name: string): Error =>
        new Error(`@browsercore/tls ${name} reached — the dynamic fallback must not be used when an engine is injected`);
    return {
        runHandshake: vi.fn(async () => {
            throw fail("runHandshake");
        }),
        generateKeyShares: vi.fn(async () => {
            throw fail("generateKeyShares");
        }),
        cipherSuiteToAead: vi.fn(() => {
            throw fail("cipherSuiteToAead");
        }),
    };
});

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

/** Everything the fake engine observed — the assertions read from this. */
interface EngineRecord {
    runHandshakeCalls: number;
    generateKeySharesCalls: number;
    cipherSuiteToAeadCalls: number;
    /** Groups received through the key-share callback quic wires into runHandshake. */
    callbackKeyShareGroups: readonly string[];
    /** The `now` (epoch seconds) quic passed for certificate validation. */
    certTimeSeconds: number | undefined;
    /** The ClientHello config the engine was handed. */
    config: ClientHelloConfig | undefined;
    /** The SNI the engine was handed. */
    serverName: string | undefined;
}

/**
 * A fake TLS 1.3 handshake engine — the http3 fake-quic pattern: a local
 * structural implementation of the consumer's contract. It performs no TLS;
 * it mutates the context the way the real engine would after a completed
 * handshake so quic's key derivation has known inputs.
 */
function createFakeHandshakeEngine(record: EngineRecord): TlsHandshakeEngine {
    return {
        async runHandshake(
            ctx: TlsHandshakeContext,
            config: ClientHelloConfig,
            serverName: string,
            _trustAnchors: readonly Uint8Array[],
            generateKeyShares: (groups: readonly string[]) => Promise<{ algorithm: NamedGroup; privateKey: Uint8Array; publicKey: Uint8Array }[]>,
            now: number,
        ): Promise<{ client: { key: Uint8Array; iv: Uint8Array }; server: { key: Uint8Array; iv: Uint8Array } }> {
            record.runHandshakeCalls += 1;
            record.config = config;
            record.serverName = serverName;
            record.certTimeSeconds = now;
            // Exercise the key-share callback wiring: quic must hand back the
            // engine's own generateKeyShares (bound to the injected crypto
            // provider), never a direct tls import.
            const pairs = await generateKeyShares(["x25519", "secp256r1"]);
            record.callbackKeyShareGroups = pairs.map((pair) => pair.algorithm);
            // A completed TLS 1.3 handshake as the real engine would leave it.
            ctx.cipherSuite = "TLS_AES_128_GCM_SHA256";
            ctx.aead = "AES-128-GCM";
            ctx.hash = "SHA-256";
            ctx.clientHsTrafficSecret = new Uint8Array(32).fill(0x11);
            ctx.serverHsTrafficSecret = new Uint8Array(32).fill(0x22);
            ctx.masterSecret = new Uint8Array(32).fill(0x33);
            ctx.alpnProtocol = "h3";
            ctx.hsTrafficReady = true;
            ctx.currentPhase = "application";
            return {
                client: { key: new Uint8Array(16).fill(0x44), iv: new Uint8Array(12).fill(0x45) },
                server: { key: new Uint8Array(16).fill(0x46), iv: new Uint8Array(12).fill(0x47) },
            };
        },
        async generateKeyShares(groups: readonly string[]): Promise<{ algorithm: NamedGroup; privateKey: Uint8Array; publicKey: Uint8Array }[]> {
            record.generateKeySharesCalls += 1;
            return groups.map((group) => ({
                algorithm: group as NamedGroup,
                privateKey: new Uint8Array(32).fill(0x6b),
                publicKey: new Uint8Array(32).fill(0x70),
            }));
        },
        cipherSuiteToAead(cipherSuite: string): "AES-128-GCM" | "AES-256-GCM" | "AES-128-CCM" | "CHACHA20-POLY1305" {
            record.cipherSuiteToAeadCalls += 1;
            switch (cipherSuite) {
                case "TLS_AES_128_GCM_SHA256":
                case "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":
                    return "AES-128-GCM";
                case "TLS_AES_256_GCM_SHA384":
                    return "AES-256-GCM";
                case "TLS_AES_128_CCM_SHA256":
                    return "AES-128-CCM";
                case "TLS_CHACHA20_POLY1305_SHA256":
                    return "CHACHA20-POLY1305";
                default:
                    throw new Error(`fake engine: unmapped cipher suite ${cipherSuite}`);
            }
        },
    };
}

/** A fresh engine record + engine pair, isolated per test. */
function freshEngine(): { record: EngineRecord; engine: TlsHandshakeEngine } {
    const record: EngineRecord = {
        runHandshakeCalls: 0,
        generateKeySharesCalls: 0,
        cipherSuiteToAeadCalls: 0,
        callbackKeyShareGroups: [],
        certTimeSeconds: undefined,
        config: undefined,
        serverName: undefined,
    };
    return { record, engine: createFakeHandshakeEngine(record) };
}

/**
 * A deterministic full canonical Clock pinned at `epochMs`. quic only reads
 * `now()` today; the remaining members are type-required surface and stay
 * functional (monotonic advances on sleep, timers fire via the event loop).
 */
function fixedClock(epochMs: number): Clock {
    let monotonicMs = 0;
    const timers = new Map<TimerHandle, ReturnType<typeof setTimeout>>();
    return {
        now: () => epochMs,
        monotonic: () => monotonicMs,
        sleep: async (ms: number) => {
            monotonicMs += ms;
            await new Promise((resolve) => {
                setTimeout(resolve, ms);
            });
        },
        setTimeout: (ms: number, fn: () => void): TimerHandle => {
            const handle = setTimeout(fn, ms);
            const token: TimerHandle = { timer: handle };
            timers.set(token, handle);
            return token;
        },
        clearTimeout: (handle: TimerHandle): void => {
            const handle0 = timers.get(handle);
            if (handle0 !== undefined) {
                clearTimeout(handle0);
                timers.delete(handle);
            }
        },
    };
}

/** A canonical ClientHello config small enough to assert identity on. */
const PROFILE: ClientHelloConfig = {
    cipherSuites: ["TLS_AES_128_GCM_SHA256"],
    extensionOrder: [0, 10, 13, 16, 23, 43, 45, 51],
    keyShareGroups: ["x25519"],
    signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
    supportedVersions: [{ name: "TLS 1.3", wire: 0x0304 }],
    serverName: "",
    alpnProtocols: ["h3"],
    grease: false,
};

const FIXED_EPOCH_MS = 1_760_000_000_000;

/** Drive a full connectQuic handshake (no skipHandshake) and close cleanly. */
async function connectWithEngine(
    engine: TlsHandshakeEngine | undefined,
    clock: Clock | undefined,
    platform: Platform | undefined,
): Promise<QuicConnection> {
    const { client } = createFakeDatagramPair();
    const conn = await connectQuic({
        transport: client,
        peer: PEER_ADDR,
        serverName: "example.com",
        initialDcid: EMPTY_CONNECTION_ID,
        initialScid: EMPTY_CONNECTION_ID,
        events: testEventProvider(),
        crypto: testCryptoProvider(),
        tlsProfile: PROFILE,
        ...(engine === undefined ? {} : { handshakeEngine: engine }),
        ...(clock === undefined ? {} : { clock }),
        ...(platform === undefined ? {} : { platform }),
    });
    await conn.handshake();
    return conn;
}

// ---------------------------------------------------------------------------
// 1. Injected engine — dynamic fallback import never taken
// ---------------------------------------------------------------------------

describe("TLS handshake engine injection (contracts TlsHandshakeEngine)", () => {
    it("drives a full connectQuic handshake through the injected engine — @browsercore/tls never imported", async () => {
        const { record, engine } = freshEngine();
        const tlsLoadsBefore = tlsImport.loads;

        const conn = await connectWithEngine(engine, undefined, undefined);
        expect(conn.id).toMatch(/^quic_/);

        // The injected engine did all the work…
        expect(record.runHandshakeCalls).toBe(1);
        expect(record.serverName).toBe("example.com");
        expect(record.config?.cipherSuites).toEqual(["TLS_AES_128_GCM_SHA256"]);
        expect(record.generateKeySharesCalls).toBe(1);
        expect(record.callbackKeyShareGroups).toEqual(["x25519", "secp256r1"]);
        // …and the deprecated dynamic @browsercore/tls fallback was NOT taken.
        expect(tlsImport.loads).toBe(tlsLoadsBefore);

        await conn.close(0n, "done");
    });

    it("runQuicHandshake with an injected engine derives all three key phases without touching tls", async () => {
        const { record, engine } = freshEngine();
        const tlsLoadsBefore = tlsImport.loads;

        const result = await runQuicHandshake(
            {
                id: "fake-transport",
                state: { state: "open" },
                write: () => Promise.resolve(),
                read: () => Promise.resolve(new Uint8Array(0)),
                close: () => Promise.resolve(),
            } as unknown as Transport,
            PROFILE,
            "example.com",
            new Uint8Array(8).fill(0xab),
            [],
            Math.floor(FIXED_EPOCH_MS / 1000),
            testCryptoProvider(),
            engine,
        );

        expect(tlsImport.loads).toBe(tlsLoadsBefore);
        expect(result.phases.map((phase) => phase.phase)).toEqual(["initial", "handshake", "application"]);
        expect(result.aead).toBe("AES-128-GCM");
        expect(result.cipherSuite).toBe("TLS_AES_128_GCM_SHA256");
        expect(result.alpnProtocol).toBe("h3");
        // The QUIC AEAD mapping for the negotiated suite is local — the fake
        // engine's cipherSuiteToAead is not consulted for the four QUIC suites.
        expect(record.cipherSuiteToAeadCalls).toBe(0);
    });

    it("mapCipherSuite delegates non-QUIC suites to the injected engine", () => {
        const { record, engine } = freshEngine();
        expect(mapCipherSuite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", engine)).toBe("AES-128-GCM");
        expect(record.cipherSuiteToAeadCalls).toBe(1);
        // Local mapping for the four QUIC suites stays engine-free.
        expect(mapCipherSuite("TLS_AES_256_GCM_SHA384", engine)).toBe("AES-256-GCM");
        expect(record.cipherSuiteToAeadCalls).toBe(1);
    });

    it("mapCipherSuite throws for non-QUIC suites when no engine is available", () => {
        expect(() => mapCipherSuite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")).toThrow(/no handshake engine injected/);
    });
});

// ---------------------------------------------------------------------------
// 2. Fallback path — dynamic default taken when no engine is injected
// ---------------------------------------------------------------------------

describe("deprecated dynamic default engine (back-compat)", () => {
    it("takes the dynamic @browsercore/tls import when no engine is injected", async () => {
        const tlsLoadsBefore = tlsImport.loads;

        // The mocked module functions throw by design: the fallback was taken
        // (factory invoked) and the handshake surfaces the module's error —
        // exactly the observable difference vs the injected path above.
        await expect(connectWithEngine(undefined, undefined, undefined)).rejects.toThrow(
            /dynamic fallback must not be used/,
        );
        expect(tlsImport.loads).toBe(tlsLoadsBefore + 1);
    });
});

// ---------------------------------------------------------------------------
// 3. Deterministic clock — cert time routed through the resolved Clock
// ---------------------------------------------------------------------------

describe("canonical Clock routing (handshake certificate time)", () => {
    it("passes Math.floor(clock.now()/1000) from QuicOptions.clock into engine.runHandshake", async () => {
        const { record, engine } = freshEngine();
        const conn = await connectWithEngine(engine, fixedClock(FIXED_EPOCH_MS), undefined);
        expect(record.certTimeSeconds).toBe(Math.floor(FIXED_EPOCH_MS / 1000));
        await conn.close(0n, "done");
    });

    it("resolves the clock from platform.time (Time ≡ Clock) when the option is absent", async () => {
        const { record, engine } = freshEngine();
        const platform: Platform = { time: fixedClock(FIXED_EPOCH_MS + 123_456) };
        const conn = await connectWithEngine(engine, undefined, platform);
        expect(record.certTimeSeconds).toBe(Math.floor((FIXED_EPOCH_MS + 123_456) / 1000));
        await conn.close(0n, "done");
    });
});

// ---------------------------------------------------------------------------
// 4. Canonical systemClock surface (contracts 0.2.6 Clock)
// ---------------------------------------------------------------------------

describe("systemClock satisfies the full canonical Clock", () => {
    it("implements now / monotonic / sleep / setTimeout / clearTimeout", async () => {
        const clock: Clock = systemClock;
        expect(typeof clock.now).toBe("function");
        expect(typeof clock.monotonic).toBe("function");
        expect(typeof clock.sleep).toBe("function");
        expect(typeof clock.setTimeout).toBe("function");
        expect(typeof clock.clearTimeout).toBe("function");

        const beforeWall = Date.now();
        const beforeMono = clock.monotonic();
        await clock.sleep(5);
        expect(clock.now()).toBeGreaterThanOrEqual(beforeWall);
        expect(clock.monotonic()).toBeGreaterThan(beforeMono);
    });

    it("setTimeout fires and clearTimeout cancels via the opaque TimerHandle", async () => {
        let fired = false;
        const handle = systemClock.setTimeout(5, () => {
            fired = true;
        });
        systemClock.clearTimeout(handle);
        await systemClock.sleep(15);
        expect(fired).toBe(false);

        let firedLater = false;
        const liveHandle = systemClock.setTimeout(5, () => {
            firedLater = true;
        });
        expect(typeof liveHandle).toBe("object");
        await systemClock.sleep(20);
        expect(firedLater).toBe(true);
    });
});
