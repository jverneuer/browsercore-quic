/**
 * Targeted coverage for uncovered branches in src/connection.ts:
 *   - lines 410-425:  wrapPacket() handshakeResult !== undefined path
 *                      (both the wrapPacketProtected branch at line 420 and
 *                       the wrapPacketUnprotected fallback at line 418)
 *   - lines 440-488:  wrapPacketProtected() body — long + short header emission
 *   - line 1018:      toTlsClientHelloConfig() else branch (tlsProfile provided)
 *   - lines 1081-1105: mapAeadToQuic() — all 4 AEAD cases + assertNever default
 *
 * Strategy: tests run with skipHandshake: true (so the read loop parks on
 * recv), then manually install a handshakeResult on the connection.
 * sendPathChallenge() drives a flush directly (no inbound datagram needed),
 * which routes outbound framing through wrapPacket -> wrapPacketProtected.
 */

import { describe, it, expect } from "vitest";
import { connectQuic } from "../src/connection.js";
import { EMPTY_CONNECTION_ID } from "../src/types.js";
import { createFakeDatagramPair, PEER_ADDR } from "./fake-transport.js";

const tick = (ms = 10) => new Promise<void>((r) => setTimeout(r, ms));

/** AEAD protection secrets (key, iv, hp) for one direction. */
function protection(keyBytes: number): {
    key: Uint8Array;
    iv: Uint8Array;
    hp: Uint8Array;
} {
    return {
        key: new Uint8Array(keyBytes).fill(0x11),
        iv: new Uint8Array(12).fill(0x22),
        hp: new Uint8Array(keyBytes).fill(0x33),
    };
}

/**
 * Build a minimal QuicHandshakeResult with a single phase. The connection's
 * getProtectionSecrets(phase) matches by phase name, so the phase must equal
 * the connection's outboundKeyPhase (default "initial") for wrapPacketProtected
 * to be reached.
 */
function handshakeResult(
    aead: string,
    keyBytes: number,
    phase = "initial",
): Record<string, unknown> {
    const p = protection(keyBytes);
    return {
        phases: [
            {
                phase,
                clientTrafficSecret: new Uint8Array(32),
                serverTrafficSecret: new Uint8Array(32),
                clientProtection: p,
                serverProtection: p,
            },
        ],
        aead,
        hash: "SHA-256",
        cipherSuite: "TLS_AES_128_GCM_SHA256",
        peerCertificate: undefined,
    };
}

function makeConn(): {
    conn: ReturnType<typeof connectQuic>;
    client: ReturnType<ReturnType<typeof createFakeDatagramPair>["client"]["constructor"]>;
    server: ReturnType<ReturnType<typeof createFakeDatagramPair>["server"]["constructor"]>;
} {
    const { client, server } = createFakeDatagramPair();
    const conn = connectQuic({
        transport: client,
        peer: PEER_ADDR,
        serverName: "example.com",
        initialDcid: EMPTY_CONNECTION_ID,
        initialScid: EMPTY_CONNECTION_ID,
        skipHandshake: true,
    });
    return { conn, client, server };
}

describe("wrapPacketProtected — handshakeResult set (connection.ts:410-425, 440-488)", () => {
    it("emits a protected long-header packet when handshakeResult has the current phase", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        // Install a handshakeResult so wrapPacket takes the protected path.
        (c as unknown as { handshakeResult: Record<string, unknown> }).handshakeResult =
            handshakeResult("AES-128-GCM", 16);
        // sendPathChallenge flushes directly (no read-loop involvement).
        c.sendPathChallenge(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);
        // Long header: the form bit (bit 7 of the first byte) is set.
        expect(data[0] !== undefined && (data[0] & 0x80) !== 0).toBe(true);
        await c.close(0n, "done");
    });

    it("emits a protected short-header (1-RTT) packet when the phase is application", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        // Phase must be "application" to exercise the short-header branch.
        (c as unknown as { handshakeResult: Record<string, unknown> }).handshakeResult =
            handshakeResult("AES-128-GCM", 16, "application");
        // Point the outbound key phase at the application secrets we installed.
        (c as unknown as { outboundKeyPhase: string }).outboundKeyPhase = "application";
        c.sendPathChallenge(new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2]));
        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);
        // Short header: the form bit (bit 7) is clear.
        expect(data[0] !== undefined && (data[0] & 0x80) === 0).toBe(true);
        await c.close(0n, "done");
    });

    it("falls through to wrapPacketUnprotected when handshakeResult lacks the current phase", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        // Provide only an "application" phase but leave outboundKeyPhase at its
        // default "initial" — getProtectionSecrets("initial") returns undefined.
        (c as unknown as { handshakeResult: Record<string, unknown> }).handshakeResult =
            handshakeResult("AES-128-GCM", 16, "application");
        c.sendPathChallenge(new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1]));
        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);
        await c.close(0n, "done");
    });
});

describe("mapAeadToQuic — all branches (connection.ts:1081-1105)", () => {
    it("handles AES-256-GCM (32-byte keys)", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        (c as unknown as { handshakeResult: Record<string, unknown> }).handshakeResult =
            handshakeResult("AES-256-GCM", 32);
        c.sendPathChallenge(new Uint8Array([2, 3, 4, 5, 6, 7, 8, 9]));
        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);
        await c.close(0n, "done");
    });

    it("handles CHACHA20-POLY1305 (32-byte keys)", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        // Note: the source switch matches the hyphenated "CHACHA20-POLY1305"
        // (QUIC naming), not the TLS underscore form.
        (c as unknown as { handshakeResult: Record<string, unknown> }).handshakeResult =
            handshakeResult("CHACHA20-POLY1305", 32);
        c.sendPathChallenge(new Uint8Array([3, 4, 5, 6, 7, 8, 9, 10]));
        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);
        await c.close(0n, "done");
    });

    it("falls back to AES-128-GCM when the handshake negotiates AES-128-CCM", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        (c as unknown as { handshakeResult: Record<string, unknown> }).handshakeResult =
            handshakeResult("AES-128-CCM", 16);
        c.sendPathChallenge(new Uint8Array([4, 5, 6, 7, 8, 9, 10, 11]));
        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);
        await c.close(0n, "done");
    });

    it("throws via assertNever for an AEAD outside the QUIC subset", async () => {
        const { conn, client, server } = makeConn();
        const c = await conn;
        const result = handshakeResult("AES-128-GCM", 16);
        // Cast an invalid AEAD to force the default branch of the switch.
        (result as { aead: string }).aead = "AES-256-CCM";
        (c as unknown as { handshakeResult: Record<string, unknown> }).handshakeResult = result;
        // close() awaits flush(), which calls wrapPacketProtected -> mapAeadToQuic.
        await expect(c.close(0n, "test")).rejects.toThrow(/Unexpected value/);
        // flush() threw before teardown; close the transport so the read loop unwinds.
        await client.close();
        await tick();
        void server;
    });
});

describe("toTlsClientHelloConfig — tlsProfile branch (connection.ts:1018)", () => {
    it("constructs the TLS profile from a provided tlsProfile option", async () => {
        const { client, server } = createFakeDatagramPair();
        const c = await connectQuic({
            transport: client,
            peer: PEER_ADDR,
            serverName: "example.com",
            initialDcid: EMPTY_CONNECTION_ID,
            initialScid: EMPTY_CONNECTION_ID,
            skipHandshake: true,
            tlsProfile: {
                cipherSuites: ["TLS_AES_128_GCM_SHA256"],
                extensionOrder: [0, 10, 13, 16, 23, 43, 45, 51],
                keyShareGroups: ["x25519"],
                signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
                supportedVersions: [{ name: "TLS 1.3", wire: 0x0304 }],
                serverName: "",
                alpnProtocols: ["h3"],
                grease: false,
            },
        });
        // The else branch ran during construction; the connection is usable.
        expect((await c.openBidirectionalStream()).id).toBe(0n);
        await c.close(0n, "done");
        void server;
    });
});
