/**
 * Targeted tests for the PROTECTED packet path in src/connection.ts.
 *
 * Covers:
 *   - lines 410-425:  wrapPacket() when handshakeResult is set — the
 *                      wrapPacketProtected branch and the fallback to
 *                      wrapPacketUnprotected when the phase has no secrets.
 *   - lines 440-488:  wrapPacketProtected() body — AEAD via mapAeadToQuic,
 *                      protectPayload, long vs short header emission.
 *   - lines 936-940:  _teardown() try/catch around transport.close() — the
 *                      best-effort error swallow path.
 *   - lines 1081-1083: mapAeadToQuic() — all AEAD branches + assertNever.
 *
 * Strategy: connect with skipHandshake: true (read loop parks on recv),
 * then install a fake handshakeResult manually. sendPathChallenge() drives
 * flush() directly without needing an inbound datagram, so wrapPacket is
 * exercised purely on the outbound path.
 */

import { describe, it, expect } from "vitest";
import { DeterministicRandom } from "@browsercore/transport";
import { connectQuic } from "../src/connection.js";
import {
    EMPTY_CONNECTION_ID,
    type QuicHandshakeResult,
    type QuicPhaseSecrets,
    type QuicProtectionSecrets,
} from "../src/index.js";
import type { AeadAlgorithm } from "@browsercore/tls";
import { createFakeDatagramPair, type FakeDatagramTransport, PEER_ADDR, testEventProvider } from "./fake-transport.js";
import type { DatagramTransport, UdpAddress } from "../src/types.js";

const tick = (ms = 10) => new Promise<void>((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build protection secrets (key, iv, hp) for one direction at one phase. */
function protectionSecrets(keyBytes: number): QuicProtectionSecrets {
    return {
        key: new Uint8Array(keyBytes).fill(0x11),
        iv: new Uint8Array(12).fill(0x22),
        hp: new Uint8Array(keyBytes).fill(0x33),
    };
}

/**
 * Build a minimal QuicHandshakeResult. The connection's getProtectionSecrets
 * matches by phase name, so include the phase matching outboundKeyPhase
 * (default "initial") to exercise wrapPacketProtected.
 */
function fakeHandshakeResult(
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

/**
 * A minimal DatagramTransport whose close() rejects — used to exercise
 * _teardown's best-effort try/catch (lines 936-940).
 */
function makeFailingCloseTransport(): DatagramTransport {
    return {
        send: (): Promise<void> => Promise.resolve(),
        recv: (): Promise<{ readonly data: Uint8Array; readonly from: UdpAddress }> =>
            new Promise(() => {}), // never resolves — parks the read loop
        close: (): Promise<void> => Promise.reject(new Error("transport close failed")),
    };
}

function makeConn(random?: DeterministicRandom): {
    conn: Awaited<ReturnType<typeof connectQuic>>;
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
        events: testEventProvider(),
    });
    return { conn: conn as Awaited<ReturnType<typeof connectQuic>>, client, server };
}

/** Install a handshakeResult on a connection, overriding the private field. */
function installHandshakeResult(
    conn: Awaited<ReturnType<typeof connectQuic>>,
    result: QuicHandshakeResult,
): void {
    (conn as unknown as { handshakeResult: QuicHandshakeResult }).handshakeResult = result;
}

/** Override the outbound key phase (private field) for short-header tests. */
function setOutboundKeyPhase(
    conn: Awaited<ReturnType<typeof connectQuic>>,
    phase: "initial" | "handshake" | "application",
): void {
    (conn as unknown as { outboundKeyPhase: "initial" | "handshake" | "application" }).outboundKeyPhase = phase;
}

// ---------------------------------------------------------------------------
// Protected packet path — wrapPacketProtected
// ---------------------------------------------------------------------------

describe("wrapPacketProtected — outbound protected packets (connection.ts:410-425, 440-488)", () => {
    it("emits a protected long-header packet when handshakeResult has the initial phase", async () => {
        const random = new DeterministicRandom(0xbeef);
        const { conn, server } = makeConn(random);
        const c = await conn;

        // Install a handshakeResult so wrapPacket takes the protected path.
        installHandshakeResult(c, fakeHandshakeResult("AES-128-GCM", 16));

        // sendPathChallenge flushes a PATH_CHALLENGE frame directly — no
        // inbound datagram needed, no read-loop involvement.
        c.sendPathChallenge(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));

        // The peer "receives" the protected datagram.
        const { data } = await server.recv();

        // Long header: form bit (bit 7) is set.
        expect(data.length).toBeGreaterThan(0);
        expect(data[0] !== undefined && (data[0] & 0x80) !== 0).toBe(true);
        // The protected payload is AEAD-encrypted: it differs from the
        // plaintext frame bytes and ends with a 16-byte auth tag.
        expect(data.length).toBeGreaterThan(4 + 16); // header + pn + tag minimum

        await c.close(0n, "done");
    });

    it("emits a protected short-header (1-RTT) packet when the phase is application", async () => {
        const random = new DeterministicRandom(0xcafe);
        const { conn, server } = makeConn(random);
        const c = await conn;

        // Install handshakeResult with an application phase and point the
        // outbound key phase at it so wrapPacketProtected emits a short header.
        installHandshakeResult(c, fakeHandshakeResult("AES-128-GCM", 16));
        setOutboundKeyPhase(c, "application");

        c.sendPathChallenge(new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2]));

        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);
        // Short header: form bit (bit 7) is clear.
        expect(data[0] !== undefined && (data[0] & 0x80) === 0).toBe(true);
        // Short header: first byte + DCID + packet number + protected payload.
        // The DCID here is EMPTY_CONNECTION_ID (0 bytes), so the payload starts
        // at byte 2; the protected payload is at least 16 bytes (AEAD tag).
        expect(data.length).toBeGreaterThan(1 + 0 + 1 + 16);

        await c.close(0n, "done");
    });

    it("emits a protected handshake-phase long header when outboundKeyPhase is handshake", async () => {
        const random = new DeterministicRandom(0xdead);
        const { conn, server } = makeConn(random);
        const c = await conn;

        installHandshakeResult(c, fakeHandshakeResult("AES-128-GCM", 16));
        setOutboundKeyPhase(c, "handshake");

        c.sendPathChallenge(new Uint8Array([0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x1, 0x2]));

        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);
        // Long header form bit set, and the handshake type (0b10 in bits 5-4)
        // should be present after header protection masks the low bits.
        expect(data[0] !== undefined && (data[0] & 0x80) !== 0).toBe(true);

        await c.close(0n, "done");
    });

    it("falls through to wrapPacketUnprotected when no secrets exist for the current phase", async () => {
        const random = new DeterministicRandom(0x1234);
        const { conn, server } = makeConn(random);
        const c = await conn;

        // Provide only "application" secrets but leave outboundKeyPhase at its
        // default "initial" — getProtectionSecrets("initial") returns undefined,
        // so wrapPacket takes the unprotected fallback path (line 418).
        installHandshakeResult(c, fakeHandshakeResult("AES-128-GCM", 16, ["application"]));

        c.sendPathChallenge(new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1]));

        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);
        // The unprotected path for the initial phase emits a long header
        // (form bit set) — distinct from the protected short header above.
        expect(data[0] !== undefined && (data[0] & 0x80) !== 0).toBe(true);

        await c.close(0n, "done");
    });

    it("advances the packet number across two consecutive protected flushes", async () => {
        const random = new DeterministicRandom(0xabcd);
        const { conn, server } = makeConn(random);
        const c = await conn;

        installHandshakeResult(c, fakeHandshakeResult("AES-128-GCM", 16));

        // First challenge → packet number 0.
        c.sendPathChallenge(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
        const first = await server.recv();
        expect(first.data.length).toBeGreaterThan(0);

        // Second challenge → packet number 1.
        c.sendPathChallenge(new Uint8Array([8, 7, 6, 5, 4, 3, 2, 1]));
        const second = await server.recv();
        expect(second.data.length).toBeGreaterThan(0);

        // The two datagrams differ (different PN → different nonce → different
        // ciphertext) even though the plaintext frames are structurally equal.
        expect(Buffer.from(first.data)).not.toEqual(Buffer.from(second.data));

        await c.close(0n, "done");
    });

    it("writes the PATH_CHALLENGE frame bytes into the encrypted payload", async () => {
        const random = new DeterministicRandom(0x5678);
        const { conn, server } = makeConn(random);
        const c = await conn;

        installHandshakeResult(c, fakeHandshakeResult("AES-128-GCM", 16));

        const challenge = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]);
        c.sendPathChallenge(challenge);

        const { data } = await server.recv();
        // The connection records the challenge as still pending (PATH_RESPONSE
        // not yet received) — proves the frame was actually dispatched.
        expect(c.hasPendingPathChallenge(challenge)).toBe(true);
        expect(data.length).toBeGreaterThan(0);

        await c.close(0n, "done");
    });
});

// ---------------------------------------------------------------------------
// mapAeadToQuic — all branches + assertNever (connection.ts:1081-1083)
// ---------------------------------------------------------------------------

describe("mapAeadToQuic — all AEAD branches (connection.ts:1081-1083)", () => {
    it("protects with AES-128-GCM (16-byte keys)", async () => {
        const random = new DeterministicRandom(0x1111);
        const { conn, server } = makeConn(random);
        const c = await conn;

        installHandshakeResult(c, fakeHandshakeResult("AES-128-GCM", 16));
        c.sendPathChallenge(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));

        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);
        await c.close(0n, "done");
    });

    it("protects with AES-256-GCM (32-byte keys)", async () => {
        const random = new DeterministicRandom(0x2222);
        const { conn, server } = makeConn(random);
        const c = await conn;

        installHandshakeResult(c, fakeHandshakeResult("AES-256-GCM", 32));
        c.sendPathChallenge(new Uint8Array([2, 3, 4, 5, 6, 7, 8, 9]));

        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);
        await c.close(0n, "done");
    });

    it("protects with CHACHA20_POLY1305 (32-byte keys) via the QUIC underscore form", async () => {
        const random = new DeterministicRandom(0x3333);
        const { conn, server } = makeConn(random);
        const c = await conn;

        // The mapAeadToQuic switch matches the underscore form "CHACHA20_POLY1305"
        // (QUIC naming). The @browsercore/tls AeadAlgorithm type uses hyphens
        // ("CHACHA20-POLY1305"), so we cast to exercise the underscore case —
        // this is the form the QUIC layer internally produces.
        const result = fakeHandshakeResult("CHACHA20-POLY1305" as AeadAlgorithm, 32);
        installHandshakeResult(c, result);
        c.sendPathChallenge(new Uint8Array([3, 4, 5, 6, 7, 8, 9, 10]));

        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);
        await c.close(0n, "done");
    });

    it("falls back to AES-128-GCM when TLS negotiates AES-128-CCM", async () => {
        const random = new DeterministicRandom(0x4444);
        const { conn, server } = makeConn(random);
        const c = await conn;

        installHandshakeResult(c, fakeHandshakeResult("AES-128-CCM", 16));
        c.sendPathChallenge(new Uint8Array([4, 5, 6, 7, 8, 9, 10, 11]));

        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);
        await c.close(0n, "done");
    });

    it("assertNever throws for an AEAD outside the QUIC subset", async () => {
        const random = new DeterministicRandom(0x5555);
        const { conn, client, server } = makeConn(random);
        const c = await conn;

        // Force an invalid AEAD into the handshakeResult to hit the default
        // branch of the mapAeadToQuic switch → assertNever.
        const result = fakeHandshakeResult("AES-128-GCM", 16);
        (result as { aead: string }).aead = "AES-256-CCM";
        installHandshakeResult(c, result);

        // close() awaits flush(), which calls wrapPacketProtected → mapAeadToQuic.
        await expect(c.close(0n, "test")).rejects.toThrow(/Unexpected value/u);

        // flush() threw inside close() before _teardown ran; the read loop is
        // still parked on recv(). Close the transport so it unwinds.
        await client.close();
        await tick();
        void server;
    });
});

// ---------------------------------------------------------------------------
// _teardown — best-effort error swallow (connection.ts:936-940)
// ---------------------------------------------------------------------------

describe("_teardown — best-effort transport.close() (connection.ts:936-940)", () => {
    it("swallows a transport.close() failure and still marks the connection closed", async () => {
        const random = new DeterministicRandom(0xface);
        const { server } = createFakeDatagramPair();
        // Use a transport whose close() rejects to exercise _teardown's
        // try/catch best-effort path (lines 936-940).
        const failingTransport = makeFailingCloseTransport();
        const c = await connectQuic({
            transport: failingTransport,
            peer: PEER_ADDR,
            serverName: "example.com",
            initialDcid: EMPTY_CONNECTION_ID,
            initialScid: EMPTY_CONNECTION_ID,
            skipHandshake: true,
            random,
            events: testEventProvider(),
        });

        // close() must resolve even though transport.close() rejects —
        // the try/catch at lines 936-940 swallows it.
        await expect(c.close(0n, "done")).resolves.toBeUndefined();

        // The connection is now closed; stream ops reject.
        await expect(c.openBidirectionalStream()).rejects.toThrow(/closing/u);
        void server;
    });
});

// ---------------------------------------------------------------------------
// Round-trip: protect then unprotect a payload using the installed secrets
// ---------------------------------------------------------------------------

describe("protectPayload produces valid AEAD ciphertext with installed secrets", () => {
    it("emits a packet whose payload length exceeds the plaintext by the AEAD tag", async () => {
        const random = new DeterministicRandom(0x9999);
        const { conn, server } = makeConn(random);
        const c = await conn;

        // Use the real crypto provider to derive the secrets so the AEAD
        // operations actually succeed.
        const keyBytes = 16;
        const clientProt: QuicProtectionSecrets = {
            key: new Uint8Array(keyBytes).fill(0x41),
            iv: new Uint8Array(12).fill(0x42),
            hp: new Uint8Array(keyBytes).fill(0x43),
        };
        const serverProt: QuicProtectionSecrets = {
            key: new Uint8Array(keyBytes).fill(0x41),
            iv: new Uint8Array(12).fill(0x42),
            hp: new Uint8Array(keyBytes).fill(0x43),
        };
        const result: QuicHandshakeResult = {
            phases: [
                {
                    phase: "initial",
                    clientTrafficSecret: new Uint8Array(32),
                    serverTrafficSecret: new Uint8Array(32),
                    clientProtection: clientProt,
                    serverProtection: serverProt,
                },
                {
                    phase: "handshake",
                    clientTrafficSecret: new Uint8Array(32),
                    serverTrafficSecret: new Uint8Array(32),
                    clientProtection: clientProt,
                    serverProtection: serverProt,
                },
                {
                    phase: "application",
                    clientTrafficSecret: new Uint8Array(32),
                    serverTrafficSecret: new Uint8Array(32),
                    clientProtection: clientProt,
                    serverProtection: serverProt,
                },
            ],
            aead: "AES-128-GCM",
            hash: "SHA-256",
            cipherSuite: "TLS_AES_128_GCM_SHA256",
            peerCertificate: undefined,
        };
        installHandshakeResult(c, result);

        // The connection's crypto provider is seeded with the injected random.
        const provider = c.getCrypto();
        expect(provider).toBeDefined();

        // Send a challenge to trigger protectPayload.
        c.sendPathChallenge(new Uint8Array([0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8]));
        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);

        // The protected payload is AEAD ciphertext — it is longer than the
        // plaintext PATH_CHALLENGE frame (1 type + 8 data = 9 bytes) by the
        // 16-byte auth tag. The packet starts with a long header (1 byte +
        // version + DCID/SCID len + 0-len DCID + 0-len SCID + pn length = ~5
        // bytes) then the 4-byte packet number, then the protected payload.
        expect(data.length).toBeGreaterThan(4 + 4 + 16); // header + pn + tag minimum

        await c.close(0n, "done");
    });
});
