/**
 * Final coverage pass for src/connection.ts.
 *
 * Targets every remaining uncovered line reported by `vitest --coverage`:
 *
 *   - Public getters/helpers: getLogger (328), toWireParameters (344),
 *     flush early-return (372), getProtectionSecrets undefined (524).
 *   - wrapPacketUnprotected short-header branch (512-514).
 *   - performHandshake + the connectQuic handshake path (537,538,541,551,552,
 *     1081,1083) — driven by mocking runQuicHandshake.
 *   - Graceful-shutdown closed-guards: onPeerClose (575), _handleFatal (930),
 *     _teardown (940).
 *   - The PROTECTED inbound dispatch path in dispatchDatagram: classifyKeyPhase
 *     (704-725), unprotectHeader (737-805), applyHeader (817-822), the AEAD
 *     unprotect call (626-628), the PacketProtectionError catch (650-652), and
 *     the frame read on the plaintext fallback (598-647).
 *
 * Strategy: connect with skipHandshake: true (the read loop parks on recv),
 * then install a fake handshakeResult on the private field so dispatchDatagram
 * takes the protected branch. By controlling which phases the fake result
 * carries we select the plaintext (no-secrets) vs. AEAD (secrets-present) path.
 */

import { describe, it, expect, vi } from "vitest";
import { DeterministicRandom } from "@browsercore/transport";
import { connectQuic } from "../src/connection.js";
import {
    EMPTY_CONNECTION_ID,
    LongPacketType,
    QuicFrameType,
    serializeFrame,
    readFrames,
    serializeShortHeader,
    serializeLongHeader,
    concatAll,
    type QuicFrame,
    type QuicHandshakeResult,
    type QuicPhaseSecrets,
    type QuicProtectionSecrets,
    type LongPacketTypeValue,
} from "../src/index.js";
import type { AeadAlgorithm } from "@browsercore/tls";
import { createFakeDatagramPair, LOCAL_ADDR, PEER_ADDR, type FakeDatagramTransport } from "./fake-transport.js";

/** Wait a macrotask so the connection's async read loop drains queued work. */
const tick = (ms = 10) => new Promise<void>((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Mock the TLS handshake so performHandshake() can complete without a server.
// Only invoked when skipHandshake is false; inert for the data-plane tests.
// ---------------------------------------------------------------------------

const { fakeHandshakeResult } = vi.hoisted(() => ({
    fakeHandshakeResult: {
        phases: [],
        aead: "AES-128-GCM",
        hash: "SHA-256",
        cipherSuite: "TLS_AES_128_GCM_SHA256",
        peerCertificate: undefined,
    } as unknown as QuicHandshakeResult,
}));

vi.mock("../src/handshake/quic-handshake.js", async (importOriginal) => {
    const original = (await importOriginal()) as Record<string, unknown>;
    return {
        ...original,
        // Resolves immediately with a result that carries no phase secrets, so
        // performHandshake sets handshakeResult + outboundKeyPhase without
        // needing a live TLS peer.
        runQuicHandshake: vi.fn(async () => fakeHandshakeResult),
    };
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Loose accessor for private methods/fields used only to drive coverage. */
function internals(conn: { readonly id: string }): Record<string, (...args: never[]) => unknown> {
    return conn as unknown as Record<string, (...args: never[]) => unknown>;
}

/** Build protection secrets (key, iv, hp) for one direction at one phase. */
function protectionSecrets(keyBytes: number): QuicProtectionSecrets {
    return {
        key: new Uint8Array(keyBytes).fill(0x11),
        iv: new Uint8Array(12).fill(0x22),
        hp: new Uint8Array(keyBytes).fill(0x33),
    };
}

/**
 * Build a minimal QuicHandshakeResult. Pass `phases: []` for the no-secrets
 * plaintext fallback, or list phases to exercise the AEAD unprotect path.
 */
function fakeResult(
    aead: AeadAlgorithm | string,
    keyBytes: number,
    phases: ReadonlyArray<"initial" | "handshake" | "application"> = ["initial", "handshake", "application"],
): QuicHandshakeResult {
    const phaseSecrets: QuicPhaseSecrets[] = phases.map((phase) => {
        const p = protectionSecrets(keyBytes);
        return {
            phase,
            clientTrafficSecret: new Uint8Array(32),
            serverTrafficSecret: new Uint8Array(32),
            clientProtection: p,
            serverProtection: p,
        };
    });
    return {
        phases: phaseSecrets,
        aead: aead as AeadAlgorithm,
        hash: keyBytes === 32 ? "SHA-384" : "SHA-256",
        cipherSuite: "TLS_AES_128_GCM_SHA256",
        peerCertificate: undefined,
    };
}

function makeConn(random?: DeterministicRandom): {
    conn: Promise<ReturnType<typeof connectQuic> extends Promise<infer C> ? C : never>;
    client: FakeDatagramTransport;
    server: FakeDatagramTransport;
} {
    const { client, server } = createFakeDatagramPair();
    const conn = connectQuic({
        transport: client,
        peer: PEER_ADDR,
        serverName: "example.com",
        initialDcid: EMPTY_CONNECTION_ID,
        initialScid: EMPTY_CONNECTION_ID,
        skipHandshake: true,
        random,
    });
    return { conn: conn as Promise<ReturnType<typeof connectQuic> extends Promise<infer C> ? C : never>, client, server };
}

/** Install a handshakeResult on a connection, overriding the private field. */
function installHandshakeResult(conn: { readonly id: string }, result: QuicHandshakeResult): void {
    (internals(conn) as { handshakeResult: QuicHandshakeResult }).handshakeResult = result;
}

/** Override the outbound key phase (private field) for short-header tests. */
function setOutboundKeyPhase(
    conn: { readonly id: string },
    phase: "initial" | "handshake" | "application",
): void {
    (internals(conn) as { outboundKeyPhase: "initial" | "handshake" | "application" }).outboundKeyPhase = phase;
}

/**
 * Build a minimal short-header packet carrying the given frames. Uses an empty
 * DCID and a 1-byte packet number so the connection parses the payload at
 * offset 2.
 */
function makePacket(...frames: QuicFrame[]): Uint8Array {
    const header = serializeShortHeader(EMPTY_CONNECTION_ID, 1, false, false);
    const pn = new Uint8Array([0x09]);
    const payload = concatAll(frames.map((f) => serializeFrame(f)));
    return concatAll([header, pn, payload]);
}

/** Build a minimal long-header packet of the given type + packet-number length. */
function makeLongPacket(
    type: LongPacketTypeValue,
    pnLength: number,
    payloadBytes: Uint8Array = new Uint8Array(0),
): Uint8Array {
    const header = serializeLongHeader(type, 0x00000001, EMPTY_CONNECTION_ID, EMPTY_CONNECTION_ID, pnLength);
    const pn = new Uint8Array(pnLength).fill(0x09);
    return concatAll([header, pn, payloadBytes]);
}

// ---------------------------------------------------------------------------
// Public getters + helpers (328, 344, 372, 524)
// ---------------------------------------------------------------------------

describe("public getters + private helpers (328, 344, 372, 524)", () => {
    it("toWireParameters converts transport parameters to wire form", async () => {
        const { conn } = makeConn();
        const c = await conn;
        // toWireParameters returns a Map<TransportParameter, Uint8Array>.
        const wire = c.toWireParameters({ initialMaxData: 1024n });
        expect(wire).toBeInstanceOf(Map);
        expect(wire.size).toBeGreaterThan(0);
        await c.close(0n, "done");
    });

    it("flush is a no-op when no outbound frames are buffered (372)", async () => {
        const { conn } = makeConn();
        const c = await conn;
        // Fresh connection: outboundFrames is empty -> early return.
        await expect(internals(c).flush()).resolves.toBeUndefined();
        await c.close(0n, "done");
    });

    it("getProtectionSecrets returns undefined before the handshake sets a result (524)", async () => {
        const { conn } = makeConn();
        const c = await conn;
        // handshakeResult is undefined here -> the undefined branch fires.
        const secrets = internals(c).getProtectionSecrets("initial") as unknown;
        expect(secrets).toBeUndefined();
        await c.close(0n, "done");
    });
});

// ---------------------------------------------------------------------------
// wrapPacketUnprotected short-header branch (512-514)
// ---------------------------------------------------------------------------

describe("wrapPacketUnprotected — application phase with no secrets (512-514)", () => {
    it("emits an unprotected short-header packet when the application phase lacks secrets", async () => {
        const random = new DeterministicRandom(0xba9);
        const { conn, server } = makeConn(random);
        const c = await conn;

        // handshakeResult set but carrying only the initial phase; outbound
        // key phase forced to "application" so wrapPacket falls through to
        // wrapPacketUnprotected's short-header branch.
        installHandshakeResult(c, fakeResult("AES-128-GCM", 16, ["initial"]));
        setOutboundKeyPhase(c, "application");

        c.sendPathChallenge(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
        const { data } = await server.recv();

        // Short header: form bit (bit 7) is clear.
        expect(data.length).toBeGreaterThan(0);
        expect(data[0] !== undefined && (data[0] & 0x80) === 0).toBe(true);
        await c.close(0n, "done");
    });
});

// ---------------------------------------------------------------------------
// performHandshake + connectQuic handshake path (537, 538, 541, 551, 552, 1081, 1083)
// ---------------------------------------------------------------------------

describe("performHandshake + connectQuic non-skip path (537-552, 1081-1083)", () => {
    it("runs performHandshake, sets handshakeResult, and advances outboundKeyPhase to application", async () => {
        const { client, server } = createFakeDatagramPair();
        // skipHandshake omitted -> connectQuic awaits performHandshake(), which
        // calls the mocked runQuicHandshake and resolves immediately.
        const c = await connectQuic({
            transport: client,
            peer: PEER_ADDR,
            serverName: "example.com",
            initialDcid: EMPTY_CONNECTION_ID,
            initialScid: EMPTY_CONNECTION_ID,
            random: new DeterministicRandom(0xface),
        });

        // performHandshake assigned handshakeResult and set outboundKeyPhase.
        const i = internals(c) as {
            handshakeResult: QuicHandshakeResult | undefined;
            outboundKeyPhase: string;
        };
        expect(i.handshakeResult).toBeDefined();
        expect(i.outboundKeyPhase).toBe("application");

        // Stream ops still work — the connection is open post-handshake. The
        // handshake itself consumed stream 0, so the next client bidi stream is 4.
        expect((await c.openBidirectionalStream()).id).toBe(4n);
        await c.close(0n, "done");
        void server;
    });
});

// ---------------------------------------------------------------------------
// Graceful-shutdown closed-guards (575, 930, 940)
// ---------------------------------------------------------------------------

describe("shutdown closed-guards (575, 930, 940)", () => {
    it("onPeerClose is a no-op once the connection is already closed (575)", async () => {
        const { conn } = makeConn();
        const c = await conn;
        await c.close(0n, "first"); // closed = true
        // A second peer close must hit the `if (this.closed) return` guard and
        // resolve without re-entering teardown.
        await expect(internals(c).onPeerClose(7n, "late") as Promise<void>).resolves.toBeUndefined();
    });

    it("_handleFatal is a no-op once the connection is already closed (930)", async () => {
        const { conn } = makeConn();
        const c = await conn;
        await c.close(0n, "first");
        // No throw, no state change — the closed guard returns early.
        expect(() => internals(c)._handleFatal(new Error("late"))).not.toThrow();
    });

    it("_teardown is a no-op once the connection is already closed (940)", async () => {
        const { conn } = makeConn();
        const c = await conn;
        await c.close(0n, "first");
        // A second teardown resolves via the `if (this.closed) return` guard.
        await expect(
            internals(c)._teardown({ kind: "error", error: new Error("late") }) as Promise<void>,
        ).resolves.toBeUndefined();
    });
});

// ---------------------------------------------------------------------------
// Protected inbound dispatch — plaintext fallback (no phase secrets)
// Covers classifyKeyPhase (711,712,714-716,718,719,722,725), unprotectHeader
// undefined branch (737-744), applyHeader (817,819,822), dispatchDatagram
// protected path (598-647).
// ---------------------------------------------------------------------------

describe("dispatchDatagram protected path — plaintext fallback (598-647, 696-822)", () => {
    it("parses a short-header plaintext packet through the protected dispatch path (application)", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        // handshakeResult set but with NO phase secrets -> every phase resolves
        // to the plaintext (no-keys) sub-path.
        installHandshakeResult(c, fakeResult("AES-128-GCM", 16, []));

        server.send(makePacket({ type: QuicFrameType.PING }), LOCAL_ADDR);
        await tick();

        // PING is relayed (no-op); the connection survives and stays open.
        expect((await c.openBidirectionalStream()).id).toBe(0n);
        await c.close(0n, "done");
    });

    it("returns early on an empty payload within the protected path (641-642)", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        installHandshakeResult(c, fakeResult("AES-128-GCM", 16, []));

        // A short-header packet with no frames -> empty payload -> early return.
        server.send(makePacket(), LOCAL_ADDR);
        await tick();
        expect((await c.openBidirectionalStream()).id).toBe(0n);
        await c.close(0n, "done");
    });

    it("classifies a long-header Initial packet as the initial phase (711,712,714-716)", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        installHandshakeResult(c, fakeResult("AES-128-GCM", 16, []));
        server.send(makeLongPacket(LongPacketType.INITIAL, 1), LOCAL_ADDR);
        await tick();
        expect((await c.openBidirectionalStream()).id).toBe(0n);
        await c.close(0n, "done");
    });

    it("classifies a long-header Handshake packet as the handshake phase (718-719)", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        installHandshakeResult(c, fakeResult("AES-128-GCM", 16, []));
        server.send(makeLongPacket(LongPacketType.HANDSHAKE, 1), LOCAL_ADDR);
        await tick();
        expect((await c.openBidirectionalStream()).id).toBe(0n);
        await c.close(0n, "done");
    });

    it("classifies 0-RTT and Retry long headers as the initial phase fallback (722)", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        installHandshakeResult(c, fakeResult("AES-128-GCM", 16, []));
        // 0-RTT (type 1) and Retry (type 3) both fall through to "initial".
        server.send(makeLongPacket(LongPacketType.ZERO_RTT, 1), LOCAL_ADDR);
        await tick();
        server.send(makeLongPacket(LongPacketType.RETRY, 1), LOCAL_ADDR);
        await tick();
        expect((await c.openBidirectionalStream()).id).toBe(0n);
        await c.close(0n, "done");
    });

    it("classifyKeyPhase returns application for an empty buffer (704-705)", async () => {
        const { conn } = makeConn();
        const c = await conn;
        const phase = internals(c).classifyKeyPhase(new Uint8Array(0)) as string;
        expect(phase).toBe("application");
        await c.close(0n, "done");
    });
});

// ---------------------------------------------------------------------------
// Protected inbound dispatch — AEAD (secrets present) path
// Covers unprotectHeader secrets-defined branch (754-805), the unprotectPayload
// call (626-628), the too-short PacketProtectionError (768-770, 650-652), and
// the generic-error catch (656).
// ---------------------------------------------------------------------------

describe("dispatchDatagram protected path — AEAD secrets present (626-628, 650-656, 754-805)", () => {
    it("throws PacketProtectionError when the packet is too short for the HP sample (768-770, 650-652)", async () => {
        const { conn, client, server } = makeConn();
        const c = await conn;
        // Carry an initial phase so classifyKeyPhase("initial") finds secrets
        // and unprotectHeader enters the AEAD branch.
        installHandshakeResult(c, fakeResult("AES-128-GCM", 16, ["initial"]));

        // Minimal Initial long header + 4-byte PN + a couple of bytes: far too
        // short for the 16-byte header-protection sample -> PacketProtectionError
        // -> caught as fatal -> connection closes.
        server.send(makeLongPacket(LongPacketType.INITIAL, 4, new Uint8Array(2)), LOCAL_ADDR);
        await tick();

        await expect(c.openBidirectionalStream()).rejects.toThrow(/closing/u);
        expect(client.isClosed).toBe(true);
    });

    it("runs the full header-protection removal then attempts AEAD decrypt (754-805, 626-628)", async () => {
        const { conn, client, server } = makeConn();
        const c = await conn;
        installHandshakeResult(c, fakeResult("AES-128-GCM", 16, ["initial"]));

        // A long-enough Initial packet passes the sample-length check; the
        // connection removes header protection, then calls unprotectPayload on
        // garbage ciphertext -> AEAD authentication fails -> fatal teardown.
        server.send(makeLongPacket(LongPacketType.INITIAL, 4, new Uint8Array(40)), LOCAL_ADDR);
        await tick();

        await expect(c.openBidirectionalStream()).rejects.toThrow(/closing/u);
        expect(client.isClosed).toBe(true);
    });

    it("exercises the AEAD secrets path for a short-header application packet", async () => {
        const { conn, client, server } = makeConn();
        const c = await conn;
        // Carry the application phase so a short header (classified
        // "application") resolves to real secrets and the AEAD path runs.
        installHandshakeResult(c, fakeResult("AES-128-GCM", 16, ["application"]));

        // Craft a short header with enough trailing bytes to satisfy the sample
        // length: 1 (first byte) + 0 (DCID) + PN (decoded from first byte) +
        // padding. The first byte encodes pnLength-1 in its low 2 bits.
        const first = 0b01000000 | 0x03; // short form, fixed bit, 4-byte PN
        const body = new Uint8Array(1 + 4 + 40);
        body[0] = first;
        server.send(body, LOCAL_ADDR);
        await tick();

        await expect(c.openBidirectionalStream()).rejects.toThrow(/closing/u);
        expect(client.isClosed).toBe(true);
    });
});
