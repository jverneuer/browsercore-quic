/**
 * Connection tests for @browsercore/quic.
 *
 * Drives connectQuic + QuicConnectionImpl over a fake datagram transport pair:
 * the read loop, stream open/accept over the wire, outbound STREAM frame
 * packing/sending, peer CONNECTION_CLOSE teardown, and the malformed-datagram
 * fatal path.
 */

import { describe, it, expect } from "vitest";
import { DeterministicRandom, type RandomSource } from "@browsercore/transport";
import { connectQuic } from "../src/connection.js";
import {
    QuicFrameType,
    EMPTY_CONNECTION_ID,
    LongPacketType,
    type PathChallengeFrame,
    type PathResponseFrame,
    type QuicFrame,
    type QuicTransportParameters,
} from "../src/types.js";
import { serializeFrame, readFrames } from "../src/frame/frame.js";
import { serializeShortHeader, serializeLongHeader } from "../src/packet/packet.js";
import { concatAll } from "../src/utils.js";
import { FakeDatagramTransport, createFakeDatagramPair, LOCAL_ADDR, PEER_ADDR, testEventProvider } from "./fake-transport.js";

/** Wait a macrotask so the connection's async read loop drains queued work. */
const tick = (ms = 10) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Build a minimal short-header packet carrying the given frames. Uses an empty
 * DCID and a 1-byte packet number so the connection (with an empty initialDcid)
 * parses the payload starting at offset 2.
 */
function makePacket(...frames: QuicFrame[]): Uint8Array {
    const header = serializeShortHeader(EMPTY_CONNECTION_ID, 1, false, false);
    const pn = new Uint8Array([0x09]);
    const payload = concatAll(frames.map((f) => serializeFrame(f)));
    return concatAll([header, pn, payload]);
}

function makeConn(params?: QuicTransportParameters) {
    const { client, server } = createFakeDatagramPair();
    const conn = connectQuic({
        transport: client,
        peer: PEER_ADDR,
        serverName: "example.com",
        initialDcid: EMPTY_CONNECTION_ID,
        initialScid: EMPTY_CONNECTION_ID,
        transportParameters: params,
        skipHandshake: true, // no TLS server in tests — exercise the data plane only
        events: testEventProvider(),
    });
    return { conn, client, server };
}

describe("connectQuic", () => {
    it("returns a connection whose id is prefixed with quic_", async () => {
        const c = await makeConn().conn;
        expect(c.id.startsWith("quic_")).toBe(true);
        await c.close(0n, "done");
    });

    it("openBidirectionalStream / openUnidirectionalStream assign correct ids", async () => {
        const c = await makeConn().conn;
        expect((await c.openBidirectionalStream()).id).toBe(0n);
        expect((await c.openBidirectionalStream()).id).toBe(4n);
        expect((await c.openUnidirectionalStream()).id).toBe(2n);
        await c.close(0n, "done");
    });
});

describe("read loop dispatch", () => {
    it("delivers STREAM data from a received datagram to an accepted stream", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        const payload = new TextEncoder().encode("hello");
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
        expect(new TextDecoder().decode(chunk)).toBe("hello");
        await c.close(0n, "done");
    });

    it("drains pending outbound STREAM sends after processing a datagram", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        const stream = await c.openBidirectionalStream();
        await stream.write(new TextEncoder().encode("out"));

        // drainSends runs after each inbound datagram; send a PING to trigger it.
        server.send(makePacket({ type: QuicFrameType.PING }), LOCAL_ADDR);
        await tick();

        // The connection packed a STREAM frame into an outbound short-header packet.
        const { data } = await server.recv();
        expect(data.length).toBeGreaterThan(2);
        await c.close(0n, "done");
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
        await expect(c.acceptBidirectionalStream()).rejects.toThrow(/closing/);
        expect(client.isClosed).toBe(true);
    });

    it("closes the connection on a malformed datagram (fatal parse error)", async () => {
        const { conn, client, server } = makeConn();
        const c = await conn;
        // 0xC0 => long header form bit, but only 1 byte provided → parse fails.
        server.send(new Uint8Array([0xc0]), LOCAL_ADDR);
        await tick();

        await expect(c.openBidirectionalStream()).rejects.toThrow(/closing/);
        expect(client.isClosed).toBe(true);
    });

    it("ignores an empty datagram", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        server.send(new Uint8Array(0), LOCAL_ADDR);
        await tick();
        // The connection stays open.
        expect((await c.openBidirectionalStream()).id).toBe(0n);
        await c.close(0n, "done");
    });

    it("handles a long-header datagram without consuming a short-header DCID", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        // A minimal Initial long header that parses but carries no payload.
        const longHeader = serializeLongHeader(
            LongPacketType.INITIAL,
            0x00000001,
            new Uint8Array([0xaa]),
            new Uint8Array([0xbb]),
            1,
        );
        server.send(longHeader, LOCAL_ADDR);
        await tick();
        // applyHeader short-circuits for long headers; the connection survives.
        expect((await c.openBidirectionalStream()).id).toBe(0n);
        await c.close(0n, "done");
    });

    it("relays handshake/control frames without acting on them", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        server.send(
            makePacket(
                { type: QuicFrameType.PADDING },
                {
                    type: QuicFrameType.ACK,
                    largestAck: 0n,
                    ackDelay: 0n,
                    ackRangeCount: 0n,
                    firstAckRange: 0n,
                    ackRanges: [],
                },
                {
                    type: QuicFrameType.ACK_ECN,
                    largestAck: 0n,
                    ackDelay: 0n,
                    ackRangeCount: 0n,
                    firstAckRange: 0n,
                    ackRanges: [],
                    ecnCounts: { ect0: 0n, ect1: 0n, ce: 0n },
                },
                { type: QuicFrameType.CRYPTO, offset: 0n, data: new Uint8Array([1]) },
                { type: QuicFrameType.NEW_TOKEN, token: new Uint8Array([1]) },
                {
                    type: QuicFrameType.NEW_CONNECTION_ID,
                    sequenceNumber: 0n,
                    retirePriorTo: 0n,
                    connectionId: new Uint8Array([1]),
                    statelessResetToken: new Uint8Array(16),
                },
                { type: QuicFrameType.RETIRE_CONNECTION_ID, sequenceNumber: 0n },
                { type: QuicFrameType.PATH_CHALLENGE, data: new Uint8Array(8) },
                { type: QuicFrameType.PATH_RESPONSE, data: new Uint8Array(8) },
                { type: QuicFrameType.HANDSHAKE_DONE },
                { type: QuicFrameType.DATA_BLOCKED, limit: 0n },
                { type: QuicFrameType.STREAMS_BLOCKED_BIDI, limit: 0n },
                { type: QuicFrameType.STREAMS_BLOCKED_UNI, limit: 0n },
            ),
            LOCAL_ADDR,
        );
        await tick();
        // Connection survived the barrage of control frames.
        expect((await c.openBidirectionalStream()).id).toBe(0n);
        await c.close(0n, "done");
    });
});

describe("close lifecycle", () => {
    it("sends a CONNECTION_CLOSE frame and closes the transport", async () => {
        const { conn, client, server } = makeConn();
        const c = await conn;
        await c.close(0n, "bye");

        // The peer received a packet whose payload decodes to a CONNECTION_CLOSE.
        const { data } = await server.recv();
        // Skip the short header (1) + packet number (1).
        const frames: QuicFrame[] = [];
        for await (const f of readFrames(() =>
            Promise.resolve(data.subarray(2).length > 0 ? data.subarray(2) : null),
        )) {
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
        await expect(c.openBidirectionalStream()).rejects.toThrow(/closing/);
        await expect(c.openUnidirectionalStream()).rejects.toThrow(/closing/);
        await expect(c.acceptBidirectionalStream()).rejects.toThrow(/closing/);
        await expect(c.acceptUnidirectionalStream()).rejects.toThrow(/closing/);
    });

    it("close is idempotent", async () => {
        const c = await makeConn().conn;
        await c.close(0n, "first");
        await c.close(0n, "second"); // must not throw
    });

    it("forwards the full set of transport parameters through connectQuic", async () => {
        const c = await makeConn({
            maxIdleTimeoutMs: 30_000,
            maxUdpPayloadSize: 1500,
            initialMaxData: 2n ** 20n,
            initialMaxStreamDataBidiLocal: 1024n,
            initialMaxStreamDataBidiRemote: 2048n,
            initialMaxStreamDataUni: 512n,
            initialMaxStreamsBidi: 10n,
            initialMaxStreamsUni: 5n,
            activeConnectionIdLimit: 4,
        }).conn;
        // Every transport-parameter branch in resolveLocalParameters executes on
        // construction; the connection still opens streams normally.
        expect((await c.openBidirectionalStream()).id).toBe(0n);
        await c.close(0n, "done");
    });
});

describe("read loop fatal error handling", () => {
    it("tears down via _handleFatal when the transport closes underneath it", async () => {
        // The read loop is parked on transport.recv(); if the underlying
        // transport dies (e.g. socket error), recv() rejects and the loop must
        // call _handleFatal → abortAll + _teardown rather than spinning forever.
        const { conn, client } = makeConn();
        const c = await conn;
        client.close(); // simulate the transport dying mid-read
        await tick();
        await tick();

        // _teardown runs best-effort transport.close() again; the connection is
        // now closed and stream operations reject.
        await expect(c.openBidirectionalStream()).rejects.toThrow(/closing/);
        expect(client.isClosed).toBe(true);
    });

    it("ignores a second CONNECTION_CLOSE (peer close after closed)", async () => {
        // The first CONNECTION_CLOSE tears the connection down; a second one must
        // hit onPeerClose's `if (this.closed) return` guard without re-entering
        // teardown. onPeerClose runs once.
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

    it("flushes outbound frames produced while dispatching a STREAM frame", async () => {
        // Dispatching a STREAM frame that crosses the per-stream replenish
        // threshold makes the manager emit a MAX_STREAM_DATA frame; the
        // connection's withOutbound must flush it to the peer.
        const { conn, server } = makeConn();
        const c = await conn;
        // Default advertised per-stream window is 256 KiB; half is the
        // replenish threshold, so 200 KiB of stream data crosses it.
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

        // The connection flushed a packet (carrying MAX_STREAM_DATA) to the peer.
        const flushed = await server.recv();
        expect(flushed.data.length).toBeGreaterThan(2);
        await c.close(0n, "done");
    });
});

describe("path validation (RFC 9000 §8.2.1, §19.17)", () => {
    /**
     * Read the next outbound short-header packet the connection sent and decode
     * its first frame. The fake transport delivers the connection's sends to the
     * peer's recv queue, so the server side "receives" what the connection sent.
     */
    async function readOutboundFrame(server: FakeDatagramTransport): Promise<QuicFrame> {
        const { data } = await server.recv();
        // Skip the short header (1 byte) + packet number (1 byte).
        let consumed = false;
        const read = (): Promise<Uint8Array | null> => {
            if (consumed) {
                return Promise.resolve(null);
            }
            consumed = true;
            return Promise.resolve(data.subarray(2));
        };
        for await (const f of readFrames(read)) {
            return f;
        }
        throw new Error("no frame in outbound datagram");
    }

    it("responds to a received PATH_CHALLENGE with a PATH_RESPONSE carrying the same 8 bytes", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        const challenge = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
        server.send(makePacket({ type: QuicFrameType.PATH_CHALLENGE, data: challenge }), LOCAL_ADDR);
        await tick();

        const response = await readOutboundFrame(server);
        expect(response.type).toBe(QuicFrameType.PATH_RESPONSE);
        const pathResponse = response as PathResponseFrame;
        expect(Array.from(pathResponse.data)).toEqual([...challenge]);
        await c.close(0n, "done");
    });

    it("echoes the exact challenge bytes for an arbitrary 8-byte payload", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        const challenge = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]);
        server.send(makePacket({ type: QuicFrameType.PATH_CHALLENGE, data: challenge }), LOCAL_ADDR);
        await tick();

        const response = await readOutboundFrame(server);
        expect(response.type).toBe(QuicFrameType.PATH_RESPONSE);
        expect(Array.from((response as PathResponseFrame).data)).toEqual([...challenge]);
        await c.close(0n, "done");
    });

    it("sends a PATH_CHALLENGE frame to the peer and records it as pending", async () => {
        const { conn, server } = makeConn();
        const c = await conn;
        const challenge = new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2]);
        c.sendPathChallenge(challenge);

        // The peer receives a PATH_CHALLENGE frame carrying the challenge bytes.
        const outbound = await readOutboundFrame(server);
        expect(outbound.type).toBe(QuicFrameType.PATH_CHALLENGE);
        expect(Array.from((outbound as PathChallengeFrame).data)).toEqual([...challenge]);

        // The connection records the challenge as pending.
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
        await readOutboundFrame(server);

        // Peer responds with a matching PATH_RESPONSE.
        server.send(makePacket({ type: QuicFrameType.PATH_RESPONSE, data: challenge }), LOCAL_ADDR);
        await tick();

        // The challenge is consumed — the path is validated.
        expect(c.hasPendingPathChallenge(challenge)).toBe(false);
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
        await readOutboundFrame(server);
        await readOutboundFrame(server);

        // Validating one does not clear the other.
        server.send(makePacket({ type: QuicFrameType.PATH_RESPONSE, data: a }), LOCAL_ADDR);
        await tick();
        expect(c.hasPendingPathChallenge(a)).toBe(false);
        expect(c.hasPendingPathChallenge(b)).toBe(true);
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

    it("rejects PATH_CHALLENGE data that is not exactly 8 bytes", async () => {
        const c = await makeConn().conn;
        expect(() => c.sendPathChallenge(new Uint8Array(7))).toThrow(/8 bytes/);
        expect(() => c.sendPathChallenge(new Uint8Array(9))).toThrow(/8 bytes/);
        expect(() => c.sendPathChallenge(new Uint8Array(0))).toThrow(/8 bytes/);
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
        const outbound = await readOutboundFrame(server);
        expect(Array.from((outbound as PathChallengeFrame).data)).toEqual([...snapshot]);
        await c.close(0n, "done");
    });
});

describe("RandomSource threading", () => {
    /**
     * A 2-state deterministic source so tests can assert exact bytes without
     * coupling to a particular algorithm. Returns `fill` for the first call,
     * then zeroes — enough to prove the connection draws from the injected
     * source for both connection ids and packet numbers.
     */
    function fakeRandom(fill: number): RandomSource {
        let first = true;
        return {
            randomBytes: (length: number): Uint8Array => {
                if (first) {
                    first = false;
                    return new Uint8Array(length).fill(fill);
                }
                return new Uint8Array(length);
            },
        };
    }

    it("defaults to nodeRandomSource when no random is injected", async () => {
        const { conn } = makeConn();
        const c = await conn;
        // No random option supplied — construction still succeeds and the
        // connection can generate ids / derive keys.
        const id = c.generateConnectionId(8);
        expect(id.length).toBe(8);
        expect(c.getCrypto()).toBeDefined();
        await c.close(0n, "done");
    });

    it("generates connection ids from the injected RandomSource", async () => {
        const random = fakeRandom(0x42);
        const { client, server } = createFakeDatagramPair();
        const c = await connectQuic({
            transport: client,
            peer: PEER_ADDR,
            serverName: "example.com",
            initialDcid: EMPTY_CONNECTION_ID,
            initialScid: EMPTY_CONNECTION_ID,
            random,
            skipHandshake: true,
            events: testEventProvider(),
        });
        const id = c.generateConnectionId(8);
        expect(Array.from(id)).toEqual([0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42]);
        void server;
        await c.close(0n, "done");
    });

    it("draws the packet-number placeholder from the injected RandomSource", async () => {
        const random = fakeRandom(0x7a);
        const { client, server } = createFakeDatagramPair();
        const c = await connectQuic({
            transport: client,
            peer: PEER_ADDR,
            serverName: "example.com",
            initialDcid: EMPTY_CONNECTION_ID,
            initialScid: EMPTY_CONNECTION_ID,
            random,
            skipHandshake: true,
            events: testEventProvider(),
        });
        // Open + write to a stream so the connection emits a packet, then read
        // the outbound datagram and inspect its packet number byte.
        const stream = await c.openBidirectionalStream();
        await stream.write(new TextEncoder().encode("x"));
        // Send a PING from the peer to trigger the read loop's send drain.
        server.send(makePacket({ type: QuicFrameType.PING }), LOCAL_ADDR);
        await tick();
        const { data } = await server.recv();
        // Short header (1 byte) + packet number (1 byte) — the packet number
        // byte is the first draw from the injected source.
        expect(data[1]).toBe(0x7a);
        await c.close(0n, "done");
    });

    it("seeds the crypto provider with the injected RandomSource", async () => {
        const random = fakeRandom(0x11);
        const { client, server } = createFakeDatagramPair();
        const c = await connectQuic({
            transport: client,
            peer: PEER_ADDR,
            serverName: "example.com",
            initialDcid: EMPTY_CONNECTION_ID,
            initialScid: EMPTY_CONNECTION_ID,
            random,
            skipHandshake: true,
            events: testEventProvider(),
        });
        // The connection's crypto provider should draw from the injected
        // source — randomBytes reflects the first deterministic draw.
        const out = c.getCrypto().randomBytes(4);
        expect(Array.from(out)).toEqual([0x11, 0x11, 0x11, 0x11]);
        void server;
        await c.close(0n, "done");
    });

    it("DeterministicRandom produces stable, seed-repeatable bytes", () => {
        const a = new DeterministicRandom(0xc0ffee);
        const b = new DeterministicRandom(0xc0ffee);
        expect(Array.from(a.randomBytes(16))).toEqual(Array.from(b.randomBytes(16)));
        // Different seed → different output.
        const c = new DeterministicRandom(0xdeed);
        expect(Array.from(c.randomBytes(16))).not.toEqual(Array.from(a.randomBytes(16)));
    });
});
