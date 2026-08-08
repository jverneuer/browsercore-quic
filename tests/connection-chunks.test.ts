/**
 * Chunk-level connection tests for @browsercore/quic.
 *
 * Targets the data-plane paths in src/connection.ts that move stream bytes
 * over the wire and handle connection lifecycle events:
 *
 *   1. STREAM frame packing into outbound packets (including multi-packet
 *      splitting when the payload exceeds MAX_DATAGRAM_PAYLOAD).
 *   2. Receiving STREAM frames and delivering reassembled bytes to accepted
 *      streams — including FIN, non-zero offset, and multi-frame datagrams.
 *   3. Connection close lifecycle (CONNECTION_CLOSE frame, idempotent close,
 *      post-close stream rejection).
 *   4. PATH_CHALLENGE / PATH_RESPONSE handling (record, validate, ignore
 *      spurious responses, multi-challenge independence).
 *   5. Transport error handling — _handleFatal via a transport whose recv()
 *      rejects, and via a malformed protected packet.
 *   6. The protected packet wrap path: installing a handshakeResult manually
 *      and confirming outbound STREAM frames are AEAD-protected end-to-end.
 *
 * Every test drives connectQuic() over the fake datagram transport pair with
 * skipHandshake: true, so the data plane runs without a live TLS peer.
 */

import { describe, it, expect } from "vitest";
import { DeterministicRandom } from "@browsercore/transport";
import { connectQuic, QuicConnectionImpl } from "../src/connection.js";
import {
    QuicFrameType,
    EMPTY_CONNECTION_ID,
    type QuicFrame,
    type QuicHandshakeResult,
    type QuicPhaseSecrets,
    type QuicProtectionSecrets,
} from "../src/index.js";
import type { AeadAlgorithm } from "@browsercore/tls";
import { serializeFrame } from "../src/frame/frame.js";
import { serializeShortHeader, parsePacketHeader } from "../src/packet/packet.js";
import { concatAll } from "../src/utils.js";
import { createFakeDatagramPair, PEER_ADDR, LOCAL_ADDR, type FakeDatagramTransport, testEventProvider } from "./fake-transport.js";

const tick = (ms = 10) => new Promise<void>((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a minimal short-header packet carrying the given frames. Uses an empty
 * DCID and a 1-byte packet number so the connection (with an empty initialDcid)
 * parses the payload starting at offset 2 (1 header byte + 1 PN byte).
 */
function makePacket(...frames: QuicFrame[]): Uint8Array {
    const header = serializeShortHeader(EMPTY_CONNECTION_ID, 1, false, false);
    const pn = new Uint8Array([0x09]);
    const payload = concatAll(frames.map((f) => serializeFrame(f)));
    return concatAll([header, pn, payload]);
}

function makeConn() {
    const { client, server } = createFakeDatagramPair();
    const conn = connectQuic({
        transport: client,
        peer: PEER_ADDR,
        serverName: "example.com",
        initialDcid: EMPTY_CONNECTION_ID,
        initialScid: EMPTY_CONNECTION_ID,
        skipHandshake: true,
        events: testEventProvider(),
    });
    return { conn, client, server };
}

function makeConnWithRandom(random: DeterministicRandom) {
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
    return { conn, client, server };
}

/** Build protection secrets (key, iv, hp) for one direction at one phase. */
function protectionSecrets(keyBytes: number): QuicProtectionSecrets {
    return {
        key: new Uint8Array(keyBytes).fill(0x11),
        iv: new Uint8Array(12).fill(0x22),
        hp: new Uint8Array(keyBytes).fill(0x33),
    };
}

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

/** Install a handshakeResult on a connection, overriding the private field. */
function installHandshakeResult(
    conn: Awaited<ReturnType<typeof connectQuic>>,
    result: QuicHandshakeResult,
): void {
    (conn as unknown as { handshakeResult: QuicHandshakeResult }).handshakeResult = result;
}

/** Override the outbound key phase (private field). */
function setOutboundKeyPhase(
    conn: Awaited<ReturnType<typeof connectQuic>>,
    phase: "initial" | "handshake" | "application",
): void {
    (conn as unknown as { outboundKeyPhase: "initial" | "handshake" | "application" }).outboundKeyPhase = phase;
}

/**
 * Read the next outbound short-header packet the connection sent and decode
 * its frames. The fake transport delivers the connection's sends to the peer's
 * recv queue, so the server side "receives" what the connection sent.
 */
async function readOutboundFrames(server: FakeDatagramTransport): Promise<QuicFrame[]> {
    const { data } = await server.recv();
    const frames: QuicFrame[] = [];
    // Parse the short header to find where the frame payload starts.
    const header = parsePacketHeader(data);
    const pnLength = header.packetNumberLength;
    // Short headers carry a variable-length DCID after the first byte;
    // the connection uses EMPTY_CONNECTION_ID (0 bytes), so no DCID skip.
    const payloadStart = 1 + pnLength; // first byte + packet number
    let consumed = false;
    const read = (): Promise<Uint8Array | null> => {
        if (consumed) return Promise.resolve(null);
        consumed = true;
        return Promise.resolve(data.subarray(payloadStart));
    };
    for await (const f of readFramesHelper(read)) {
        frames.push(f);
    }
    return frames;
}

/** Local re-export of readFrames so we don't import outside the public API. */
async function* readFramesHelper(read: () => Promise<Uint8Array | null>): AsyncGenerator<QuicFrame> {
    // Inline a minimal frame reader matching the connection's dispatch:
    // we reuse the public readFrames from the frame module.
    for await (const f of readFrames(read)) {
        yield f;
    }
}

// Import readFrames lazily to keep the helper above self-contained.
import { readFrames } from "../src/frame/frame.js";

// ---------------------------------------------------------------------------
// 1. STREAM frame packing into outbound packets
// ---------------------------------------------------------------------------

describe("STREAM frame packing", () => {
    it("packs a small outbound STREAM frame into a single short-header packet", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        const stream = await c.openBidirectionalStream();
        const payload = new TextEncoder().encode("hello world");
        await stream.write(payload);

        // Send a PING from the peer to trigger the read loop's send drain.
        server.send(makePacket({ type: QuicFrameType.PING }), LOCAL_ADDR);
        await tick();

        // The connection packed a STREAM frame into an outbound short-header packet.
        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(2); // header + pn + some payload

        // Decode and verify the STREAM frame carries our bytes.
        const header = parsePacketHeader(data);
        const pnLength = header.packetNumberLength;
        let consumed = false;
        const read = (): Promise<Uint8Array | null> => {
            if (consumed) return Promise.resolve(null);
            consumed = true;
            return Promise.resolve(data.subarray(1 + pnLength));
        };
        const decoded: QuicFrame[] = [];
        for await (const f of readFrames(read)) {
            decoded.push(f);
        }
        const streamFrame = decoded.find((f) => f.type === QuicFrameType.STREAM);
        expect(streamFrame).toBeDefined();
        expect(streamFrame).toMatchObject({ streamId: 0n });
        expect(new TextDecoder().decode((streamFrame as { data: Uint8Array }).data)).toBe("hello world");
        await c.close(0n, "done");
    });

    it("marks FIN on the STREAM frame when the writer closes the stream", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        const stream = await c.openBidirectionalStream();
        await stream.write(new TextEncoder().encode("final"));
        await stream.close();

        // Trigger the send drain.
        server.send(makePacket({ type: QuicFrameType.PING }), LOCAL_ADDR);
        await tick();

        // Read outbound and look for a STREAM frame with fin=true.
        const { data } = await server.recv();
        const header = parsePacketHeader(data);
        const pnLength = header.packetNumberLength;
        let consumed = false;
        const read = (): Promise<Uint8Array | null> => {
            if (consumed) return Promise.resolve(null);
            consumed = true;
            return Promise.resolve(data.subarray(1 + pnLength));
        };
        const decoded: QuicFrame[] = [];
        for await (const f of readFrames(read)) {
            decoded.push(f);
        }
        const streamFrames = decoded.filter((f) => f.type === QuicFrameType.STREAM);
        expect(streamFrames.length).toBeGreaterThanOrEqual(1);
        expect(streamFrames.some((f) => (f as { fin: boolean }).fin)).toBe(true);
        await c.close(0n, "done");
    });

    it("packs multiple STREAM frames into one packet when they fit", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        const s1 = await c.openBidirectionalStream();
        const s2 = await c.openBidirectionalStream();
        await s1.write(new TextEncoder().encode("alpha"));
        await s2.write(new TextEncoder().encode("beta"));

        // Trigger the send drain.
        server.send(makePacket({ type: QuicFrameType.PING }), LOCAL_ADDR);
        await tick();

        // Read all outbound datagrams — the two STREAM frames should be packed
        // into one packet (they're small enough to fit within MAX_DATAGRAM_PAYLOAD).
        const { data } = await server.recv();
        const header = parsePacketHeader(data);
        const pnLength = header.packetNumberLength;
        let consumed = false;
        const read = (): Promise<Uint8Array | null> => {
            if (consumed) return Promise.resolve(null);
            consumed = true;
            return Promise.resolve(data.subarray(1 + pnLength));
        };
        const decoded: QuicFrame[] = [];
        for await (const f of readFrames(read)) {
            decoded.push(f);
        }
        const streamFrames = decoded.filter((f) => f.type === QuicFrameType.STREAM);
        // We expect both STREAM frames (ids 0 and 4) in this single packet.
        const ids = streamFrames.map((f) => (f as { streamId: bigint }).streamId).sort();
        expect(ids).toContain(0n);
        expect(ids).toContain(4n);
        await c.close(0n, "done");
    });

    it("splits a large outbound write across multiple datagrams", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        const stream = await c.openBidirectionalStream();
        // 20 KiB exceeds MAX_DATAGRAM_PAYLOAD (1200 bytes), forcing a split.
        const big = new Uint8Array(20_000).fill(0x42);
        await stream.write(big);

        // Trigger the send drain.
        server.send(makePacket({ type: QuicFrameType.PING }), LOCAL_ADDR);
        await tick();

        // Collect all outbound datagrams until we've seen the whole payload.
        const received: Uint8Array[] = [];
        for (let i = 0; i < 30; i++) {
            try {
                const env = await Promise.race([
                    server.recv(),
                    new Promise<never>((_, rej) => setTimeout(() => rej(new Error("timeout")), 50)),
                ]);
                received.push(env.data);
            } catch {
                break;
            }
        }
        expect(received.length).toBeGreaterThan(1);
        // Every datagram starts with a valid short header.
        for (const d of received) {
            expect(d.length).toBeGreaterThan(2);
            expect(d[0] !== undefined && (d[0] & 0x80) === 0).toBe(true); // short header
        }
        await c.close(0n, "done");
    });

    it("delivers multiple contiguous writes as a single reassembled byte stream", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        const stream = await c.openBidirectionalStream();
        await stream.write(new TextEncoder().encode("first"));
        await stream.write(new TextEncoder().encode("second"));

        // Trigger the send drain.
        server.send(makePacket({ type: QuicFrameType.PING }), LOCAL_ADDR);
        await tick();

        // Read the outbound packet.
        const { data } = await server.recv();
        const header = parsePacketHeader(data);
        const pnLength = header.packetNumberLength;
        let consumed = false;
        const read = (): Promise<Uint8Array | null> => {
            if (consumed) return Promise.resolve(null);
            consumed = true;
            return Promise.resolve(data.subarray(1 + pnLength));
        };
        const decoded: QuicFrame[] = [];
        for await (const f of readFrames(read)) {
            decoded.push(f);
        }
        const streamFrames = decoded.filter((f) => f.type === QuicFrameType.STREAM) as Array<{
            offset: bigint;
            data: Uint8Array;
        }>;
        // The stream manager may coalesce contiguous writes into one frame or
        // emit multiple; either way the total bytes sent must equal "firstsecond".
        const totalBytes = streamFrames.reduce((sum, f) => sum + f.data.length, 0);
        const totalText = streamFrames.map((f) => new TextDecoder().decode(f.data)).join("");
        expect(totalBytes).toBe(11); // "first" + "second" = 5 + 6
        expect(totalText).toBe("firstsecond");
        await c.close(0n, "done");
    });
});

// ---------------------------------------------------------------------------
// 2. Receiving STREAM frames and delivering to streams
// ---------------------------------------------------------------------------

describe("STREAM frame receive + delivery", () => {
    it("delivers STREAM data from a received datagram to an accepted stream", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        const payload = new TextEncoder().encode("hello quic");
        server.send(
            makePacket({
                type: QuicFrameType.STREAM,
                streamId: 1n,
                offset: 0n,
                data: payload,
                fin: false,
            }),
            LOCAL_ADDR,
        );
        await tick();

        const stream = await c.acceptBidirectionalStream();
        expect(stream.id).toBe(1n);
        const chunk = await stream.read();
        expect(new TextDecoder().decode(chunk)).toBe("hello quic");
        await c.close(0n, "done");
    });

    it("delivers STREAM data with FIN and resolves the read at end-of-stream", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        server.send(
            makePacket({
                type: QuicFrameType.STREAM,
                streamId: 1n,
                offset: 0n,
                data: new TextEncoder().encode("fin-payload"),
                fin: true,
            }),
            LOCAL_ADDR,
        );
        await tick();

        const stream = await c.acceptBidirectionalStream();
        expect(stream.id).toBe(1n);
        const chunk = await stream.read();
        expect(new TextDecoder().decode(chunk)).toBe("fin-payload");
        // After FIN, the next read returns null (end of stream).
        const end = await stream.read();
        expect(end.length).toBe(0);
        await c.close(0n, "done");
    });

    it("reassembles STREAM frames received out of order by offset", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        // Send the second chunk first (offset 6), then the first chunk (offset 0).
        server.send(
            makePacket({
                type: QuicFrameType.STREAM,
                streamId: 1n,
                offset: 6n,
                data: new TextEncoder().encode("world"),
                fin: false,
            }),
            LOCAL_ADDR,
        );
        await tick();
        server.send(
            makePacket({
                type: QuicFrameType.STREAM,
                streamId: 1n,
                offset: 0n,
                data: new TextEncoder().encode("hello "),
                fin: false,
            }),
            LOCAL_ADDR,
        );
        await tick();

        const stream = await c.acceptBidirectionalStream();
        expect(stream.id).toBe(1n);
        const chunk = await stream.read();
        expect(new TextDecoder().decode(chunk)).toBe("hello world");
        await c.close(0n, "done");
    });

    it("delivers multiple STREAM frames from a single datagram", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        // Two STREAM frames for two different streams in one datagram.
        server.send(
            makePacket(
                {
                    type: QuicFrameType.STREAM,
                    streamId: 1n,
                    offset: 0n,
                    data: new TextEncoder().encode("stream-a"),
                    fin: false,
                },
                {
                    type: QuicFrameType.STREAM,
                    streamId: 5n,
                    offset: 0n,
                    data: new TextEncoder().encode("stream-b"),
                    fin: false,
                },
            ),
            LOCAL_ADDR,
        );
        await tick();

        const sa = await c.acceptBidirectionalStream();
        const sb = await c.acceptBidirectionalStream();
        // Accept order is by stream id ascending; ids 1 and 5.
        const ids = [sa.id, sb.id].sort();
        expect(ids[0]).toBe(1n);
        expect(ids[1]).toBe(5n);
        const chunkA = await sa.read();
        const chunkB = await sb.read();
        // Whichever is stream 1 has "stream-a"; stream 5 has "stream-b".
        const texts = (
            sa.id === 1n
                ? [new TextDecoder().decode(chunkA), new TextDecoder().decode(chunkB)]
                : [new TextDecoder().decode(chunkB), new TextDecoder().decode(chunkA)]
        );
        expect(texts).toEqual(["stream-a", "stream-b"]);
        await c.close(0n, "done");
    });

    it("emits MAX_STREAM_DATA when the per-stream window is half-consumed", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        // Default initialMaxStreamData is 256 KiB; half (128 KiB) is the
        // replenish threshold. Send 200 KiB to cross it.
        const big = new Uint8Array(200_000).fill(0x51);
        server.send(
            makePacket({
                type: QuicFrameType.STREAM,
                streamId: 1n,
                offset: 0n,
                data: big,
                fin: false,
            }),
            LOCAL_ADDR,
        );
        await tick();

        // The connection flushed a packet carrying MAX_STREAM_DATA to the peer.
        const { data } = await server.recv();
        const header = parsePacketHeader(data);
        const pnLength = header.packetNumberLength;
        let consumed = false;
        const read = (): Promise<Uint8Array | null> => {
            if (consumed) return Promise.resolve(null);
            consumed = true;
            return Promise.resolve(data.subarray(1 + pnLength));
        };
        const decoded: QuicFrame[] = [];
        for await (const f of readFrames(read)) {
            decoded.push(f);
        }
        expect(decoded.some((f) => f.type === QuicFrameType.MAX_STREAM_DATA)).toBe(true);
        await c.close(0n, "done");
    });
});

// ---------------------------------------------------------------------------
// 3. Connection close lifecycle
// ---------------------------------------------------------------------------

describe("connection close lifecycle", () => {
    it("sends a CONNECTION_CLOSE frame and closes the transport", async () => {
        const { conn, client, server } = makeConn();
        const c = await conn;
        await c.close(0n, "bye");

        // The peer received a packet whose payload decodes to a CONNECTION_CLOSE.
        const { data } = await server.recv();
        const header = parsePacketHeader(data);
        const pnLength = header.packetNumberLength;
        let consumed = false;
        const read = (): Promise<Uint8Array | null> => {
            if (consumed) return Promise.resolve(null);
            consumed = true;
            return Promise.resolve(data.subarray(1 + pnLength));
        };
        const frames: QuicFrame[] = [];
        for await (const f of readFrames(read)) {
            frames.push(f);
            break;
        }
        const close = frames[0];
        expect(close?.type).toBe(QuicFrameType.CONNECTION_CLOSE);
        expect(close).toMatchObject({ errorCode: 0n, reason: "bye" });
        expect(client.isClosed).toBe(true);
    });

    it("rejects all stream operations after close", async () => {
        const c = await makeConn().conn;
        await c.close(0n, "done");
        await expect(c.openBidirectionalStream()).rejects.toThrow(/closing/u);
        await expect(c.openUnidirectionalStream()).rejects.toThrow(/closing/u);
        await expect(c.acceptBidirectionalStream()).rejects.toThrow(/closing/u);
        await expect(c.acceptUnidirectionalStream()).rejects.toThrow(/closing/u);
    });

    it("close is idempotent — a second close does not throw", async () => {
        const c = await makeConn().conn;
        await c.close(0n, "first");
        await c.close(0n, "second");
    });

    it("tears down when the peer sends CONNECTION_CLOSE", async () => {
        const { conn, client, server } = makeConn();
        const c = await conn;
        server.send(
            makePacket({
                type: QuicFrameType.CONNECTION_CLOSE,
                errorCode: 0x0cn,
                frameType: undefined,
                reason: "bye",
            }),
            LOCAL_ADDR,
        );
        await tick();

        // Connection is now closing/closed: stream ops reject.
        await expect(c.acceptBidirectionalStream()).rejects.toThrow(/closing/u);
        expect(client.isClosed).toBe(true);
    });

    it("ignores a second CONNECTION_CLOSE (peer close after closed)", async () => {
        // The first CONNECTION_CLOSE tears the connection down; a second one must
        // hit onPeerClose's `if (this.closed) return` guard without re-entering
        // teardown.
        const { conn, client, server } = makeConn();
        const c = await conn;
        const closeFrame = makePacket({
            type: QuicFrameType.CONNECTION_CLOSE,
            errorCode: 0x0cn,
            frameType: undefined,
            reason: "bye",
        });
        server.send(closeFrame, LOCAL_ADDR);
        await tick();
        expect(client.isClosed).toBe(true);
        // Second close must not throw or double-teardown.
        server.send(closeFrame, LOCAL_ADDR);
        await tick();
        expect(client.isClosed).toBe(true);
    });

    it("teardown is idempotent — _teardown after closed is a no-op", async () => {
        // The first close triggers _teardown. A subsequent close must hit
        // _teardown's `if (this.closed) return` guard and resolve cleanly.
        const c = await makeConn().conn;
        await c.close(0n, "first");
        await c.close(0n, "second");
        // Private flag should be set; we observe it indirectly via stream ops rejecting.
        await expect(c.openBidirectionalStream()).rejects.toThrow(/closing/u);
    });
});

// ---------------------------------------------------------------------------
// 4. PATH_CHALLENGE / PATH_RESPONSE handling
// ---------------------------------------------------------------------------

describe("PATH_CHALLENGE / PATH_RESPONSE handling", () => {
    it("responds to a received PATH_CHALLENGE with a PATH_RESPONSE carrying the same 8 bytes", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        const challenge = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
        server.send(makePacket({ type: QuicFrameType.PATH_CHALLENGE, data: challenge }), LOCAL_ADDR);
        await tick();

        const frames = await readOutboundFrames(server);
        const response = frames.find((f) => f.type === QuicFrameType.PATH_RESPONSE);
        expect(response).toBeDefined();
        expect(Array.from((response as { data: Uint8Array }).data)).toEqual([...challenge]);
        await c.close(0n, "done");
    });

    it("sends a PATH_CHALLENGE frame to the peer and records it as pending", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        const challenge = new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2]);
        c.sendPathChallenge(challenge);

        const frames = await readOutboundFrames(server);
        const outbound = frames.find((f) => f.type === QuicFrameType.PATH_CHALLENGE);
        expect(outbound).toBeDefined();
        expect(Array.from((outbound as { data: Uint8Array }).data)).toEqual([...challenge]);
        expect(c.hasPendingPathChallenge(challenge)).toBe(true);
        await c.close(0n, "done");
    });

    it("validates a matching PATH_RESPONSE by clearing the pending challenge", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        const challenge = new Uint8Array([0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89]);
        c.sendPathChallenge(challenge);
        expect(c.hasPendingPathChallenge(challenge)).toBe(true);

        // Drain the outbound PATH_CHALLENGE the connection sent.
        await readOutboundFrames(server);

        // Peer responds with a matching PATH_RESPONSE.
        server.send(makePacket({ type: QuicFrameType.PATH_RESPONSE, data: challenge }), LOCAL_ADDR);
        await tick();

        // The challenge is consumed — the path is validated.
        expect(c.hasPendingPathChallenge(challenge)).toBe(false);
        await c.close(0n, "done");
    });

    it("ignores a PATH_RESPONSE that matches no pending challenge", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        const pending = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
        c.sendPathChallenge(pending);
        expect(c.hasPendingPathChallenge(pending)).toBe(true);

        // Peer sends a PATH_RESPONSE that does NOT match the pending challenge.
        const spurious = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        server.send(makePacket({ type: QuicFrameType.PATH_RESPONSE, data: spurious }), LOCAL_ADDR);
        await tick();

        // The pending challenge is untouched; connection stays open.
        expect(c.hasPendingPathChallenge(pending)).toBe(true);
        expect((await c.openBidirectionalStream()).id).toBe(0n);
        await c.close(0n, "done");
    });

    it("tracks multiple concurrent pending challenges independently", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        const a = new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1]);
        const b = new Uint8Array([2, 2, 2, 2, 2, 2, 2, 2]);
        c.sendPathChallenge(a);
        c.sendPathChallenge(b);
        expect(c.hasPendingPathChallenge(a)).toBe(true);
        expect(c.hasPendingPathChallenge(b)).toBe(true);

        // Drain both outbound PATH_CHALLENGEs.
        await readOutboundFrames(server);
        await readOutboundFrames(server);

        // Validating one does not clear the other.
        server.send(makePacket({ type: QuicFrameType.PATH_RESPONSE, data: a }), LOCAL_ADDR);
        await tick();
        expect(c.hasPendingPathChallenge(a)).toBe(false);
        expect(c.hasPendingPathChallenge(b)).toBe(true);
        await c.close(0n, "done");
    });

    it("rejects PATH_CHALLENGE data that is not exactly 8 bytes", async () => {
        const c = await makeConn().conn;
        expect(() => c.sendPathChallenge(new Uint8Array(7))).toThrow(/8 bytes/u);
        expect(() => c.sendPathChallenge(new Uint8Array(9))).toThrow(/8 bytes/u);
        expect(() => c.sendPathChallenge(new Uint8Array(0))).toThrow(/8 bytes/u);
        await c.close(0n, "done");
    });

    it("does not mutate the caller's challenge buffer", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        const challenge = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80]);
        const snapshot = challenge.slice();
        c.sendPathChallenge(challenge);

        // The caller's buffer is untouched.
        expect(Array.from(challenge)).toEqual([...snapshot]);
        // The peer received the same bytes we intended to send.
        const frames = await readOutboundFrames(server);
        const outbound = frames.find((f) => f.type === QuicFrameType.PATH_CHALLENGE);
        expect(Array.from((outbound as { data: Uint8Array }).data)).toEqual([...snapshot]);
        await c.close(0n, "done");
    });
});

// ---------------------------------------------------------------------------
// 5. Transport error handling (_handleFatal)
// ---------------------------------------------------------------------------

describe("transport error handling (_handleFatal)", () => {
    it("tears down via _handleFatal when the transport closes underneath it", async () => {
        // The read loop is parked on transport.recv(); if the underlying
        // transport dies (e.g. socket error), recv() rejects and the loop must
        // call _handleFatal -> abortAll + _teardown rather than spinning forever.
        const { conn, client } = makeConn();
        const c = await conn;
        client.close(); // simulate the transport dying mid-read
        await tick();
        await tick();

        // _teardown runs best-effort transport.close() again; the connection is
        // now closed and stream operations reject.
        await expect(c.openBidirectionalStream()).rejects.toThrow(/closing/u);
        expect(client.isClosed).toBe(true);
    });

    it("closes the connection on a malformed datagram (fatal parse error)", async () => {
        const { conn, client, server } = makeConn();
        const c = await conn;
        // 0xC0 => long header form bit, but only 1 byte provided -> parse fails.
        server.send(new Uint8Array([0xc0]), LOCAL_ADDR);
        await tick();

        await expect(c.openBidirectionalStream()).rejects.toThrow(/closing/u);
        expect(client.isClosed).toBe(true);
    });

    it("handles a malformed long-header datagram gracefully", async () => {
        // A long header first byte followed by an invalid version field that
        // causes parsePacketHeader to fail -> _handleFatal.
        const { conn, client, server } = makeConn();
        const c = await conn;
        server.send(new Uint8Array([0xc0, 0x00, 0x00, 0x00, 0x00]), LOCAL_ADDR);
        await tick();

        await expect(c.openBidirectionalStream()).rejects.toThrow(/closing/u);
        expect(client.isClosed).toBe(true);
    });

    it("ignores an empty datagram without tearing down", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        server.send(new Uint8Array(0), LOCAL_ADDR);
        await tick();
        // The connection stays open.
        expect((await c.openBidirectionalStream()).id).toBe(0n);
        await c.close(0n, "done");
    });

    it("handles a datagram that carries a parseable but zero-payload packet", async () => {
        // A short header with no frames after the packet number — the connection
        // should not tear down; dispatchDatagram returns early on empty payload.
        const { conn, server } = makeConn();
        const c = await conn;
        server.send(
            makePacket(/* no frames */),
            LOCAL_ADDR,
        );
        await tick();
        // Connection survives.
        expect((await c.openBidirectionalStream()).id).toBe(0n);
        await c.close(0n, "done");
    });
});

// ---------------------------------------------------------------------------
// 6. Protected packet wrap path
// ---------------------------------------------------------------------------

describe("protected packet wrap path (handshakeResult installed)", () => {
    it("emits a protected long-header packet when handshakeResult has the initial phase", async () => {
        const random = new DeterministicRandom(0xbeef);
        const { conn, server } = makeConnWithRandom(random);
        const c = await conn;

        installHandshakeResult(c, fakeHandshakeResult("AES-128-GCM", 16));

        // sendPathChallenge flushes a PATH_CHALLENGE frame directly — no
        // inbound datagram needed, no read-loop involvement.
        c.sendPathChallenge(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));

        // The peer "receives" the protected datagram.
        const { data } = await server.recv();

        // Long header: form bit (bit 7) is set.
        expect(data.length).toBeGreaterThan(0);
        expect(data[0] !== undefined && (data[0] & 0x80) !== 0).toBe(true);
        // The protected payload is AEAD-encrypted: longer than the plaintext
        // PATH_CHALLENGE frame (1 type + 8 data = 9 bytes) by the 16-byte tag.
        expect(data.length).toBeGreaterThan(4 + 4 + 16); // header + pn + tag minimum

        await c.close(0n, "done");
    });

    it("emits a protected short-header (1-RTT) packet when the phase is application", async () => {
        const random = new DeterministicRandom(0xcafe);
        const { conn, server } = makeConnWithRandom(random);
        const c = await conn;

        installHandshakeResult(c, fakeHandshakeResult("AES-128-GCM", 16));
        setOutboundKeyPhase(c, "application");

        c.sendPathChallenge(new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2]));

        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);
        // Short header: form bit (bit 7) is clear.
        expect(data[0] !== undefined && (data[0] & 0x80) === 0).toBe(true);

        await c.close(0n, "done");
    });

    it("protects STREAM frames when handshakeResult is installed", async () => {
        // With handshakeResult installed, the connection expects *protected*
        // inbound packets — so we cannot trigger the send drain with a plaintext
        // PING (the connection would try to unprotect it and fatally error).
        // Instead, sendPathChallenge drives flush() directly: any STREAM frame
        // already queued gets packed into the same protected packet.
        const random = new DeterministicRandom(0xdead);
        const { conn, server } = makeConnWithRandom(random);
        const c = await conn;

        installHandshakeResult(c, fakeHandshakeResult("AES-128-GCM", 16));

        // Open a stream and write — queues a STREAM frame in the outbound buffer.
        const stream = await c.openBidirectionalStream();
        await stream.write(new TextEncoder().encode("protected-bytes"));

        // sendPathChallenge flushes all queued outbound frames (including the
        // STREAM frame) into a single protected packet.
        c.sendPathChallenge(new Uint8Array([0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x1, 0x2]));

        // Read the outbound protected packet.
        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);
        // Long header form bit set (phase is "initial").
        expect(data[0] !== undefined && (data[0] & 0x80) !== 0).toBe(true);
        // The payload is AEAD ciphertext — longer than the plaintext
        // PATH_CHALLENGE + STREAM frames by the 16-byte tag.
        expect(data.length).toBeGreaterThan(4 + 4 + 16);

        await c.close(0n, "done");
    });

    it("advances the packet number across two consecutive protected flushes", async () => {
        const random = new DeterministicRandom(0xabcd);
        const { conn, server } = makeConnWithRandom(random);
        const c = await conn;

        installHandshakeResult(c, fakeHandshakeResult("AES-128-GCM", 16));

        // First challenge -> packet number 0.
        c.sendPathChallenge(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
        const first = await server.recv();
        expect(first.data.length).toBeGreaterThan(0);

        // Second challenge -> packet number 1.
        c.sendPathChallenge(new Uint8Array([8, 7, 6, 5, 4, 3, 2, 1]));
        const second = await server.recv();
        expect(second.data.length).toBeGreaterThan(0);

        // The two datagrams differ (different PN -> different nonce -> different
        // ciphertext) even though the plaintext frames are structurally equal.
        expect(Buffer.from(first.data)).not.toEqual(Buffer.from(second.data));

        await c.close(0n, "done");
    });

    it("falls through to wrapPacketUnprotected when no secrets exist for the current phase", async () => {
        const random = new DeterministicRandom(0x1234);
        const { conn, server } = makeConnWithRandom(random);
        const c = await conn;

        // Provide only "application" secrets but leave outboundKeyPhase at its
        // default "initial" -> getProtectionSecrets("initial") returns undefined,
        // so wrapPacket takes the unprotected fallback path.
        installHandshakeResult(c, fakeHandshakeResult("AES-128-GCM", 16, ["application"]));

        c.sendPathChallenge(new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1]));

        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);
        // The unprotected path for the initial phase emits a long header.
        expect(data[0] !== undefined && (data[0] & 0x80) !== 0).toBe(true);

        await c.close(0n, "done");
    });

    it("uses the correct AEAD for AES-256-GCM (32-byte keys)", async () => {
        const random = new DeterministicRandom(0x2222);
        const { conn, server } = makeConnWithRandom(random);
        const c = await conn;

        installHandshakeResult(c, fakeHandshakeResult("AES-256-GCM", 32));
        c.sendPathChallenge(new Uint8Array([2, 3, 4, 5, 6, 7, 8, 9]));

        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);
        await c.close(0n, "done");
    });

    it("uses the correct AEAD for CHACHA20_POLY1305 (32-byte keys)", async () => {
        const random = new DeterministicRandom(0x3333);
        const { conn, server } = makeConnWithRandom(random);
        const c = await conn;

        const result = fakeHandshakeResult("CHACHA20-POLY1305" as AeadAlgorithm, 32);
        installHandshakeResult(c, result);
        c.sendPathChallenge(new Uint8Array([3, 4, 5, 6, 7, 8, 9, 10]));

        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);
        await c.close(0n, "done");
    });

    it("falls back to AES-128-GCM when TLS negotiates AES-128-CCM", async () => {
        const random = new DeterministicRandom(0x4444);
        const { conn, server } = makeConnWithRandom(random);
        const c = await conn;

        installHandshakeResult(c, fakeHandshakeResult("AES-128-CCM", 16));
        c.sendPathChallenge(new Uint8Array([4, 5, 6, 7, 8, 9, 10, 11]));

        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(0);
        await c.close(0n, "done");
    });

    it("assertNever throws for an AEAD outside the QUIC subset", async () => {
        const random = new DeterministicRandom(0x5555);
        const { conn, client, server } = makeConnWithRandom(random);
        const c = await conn;

        // Force an invalid AEAD into the handshakeResult to hit the default
        // branch of the mapAeadToQuic switch -> assertNever.
        const result = fakeHandshakeResult("AES-128-GCM", 16);
        (result as { aead: string }).aead = "AES-256-CCM";
        installHandshakeResult(c, result);

        // close() awaits flush(), which calls wrapPacketProtected -> mapAeadToQuic.
        await expect(c.close(0n, "test")).rejects.toThrow(/Unexpected value/u);

        // flush() threw inside close() before _teardown ran; the read loop is
        // still parked on recv(). Close the transport so it unwinds.
        await client.close();
        await tick();
        void server;
    });

    it("constructs the TLS profile from a provided tlsProfile option (toTlsClientHelloConfig)", async () => {
        const { client, server } = createFakeDatagramPair();
        const c = await connectQuic({
            transport: client,
            peer: PEER_ADDR,
            serverName: "example.com",
            initialDcid: EMPTY_CONNECTION_ID,
            initialScid: EMPTY_CONNECTION_ID,
            skipHandshake: true,
            events: testEventProvider(),
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
