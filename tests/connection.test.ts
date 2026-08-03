/**
 * Connection tests for @browsercore/quic.
 *
 * Drives connectQuic + QuicConnectionImpl over a fake datagram transport pair:
 * the read loop, stream open/accept over the wire, outbound STREAM frame
 * packing/sending, peer CONNECTION_CLOSE teardown, and the malformed-datagram
 * fatal path.
 */

import { describe, it, expect } from "vitest";
import { connectQuic } from "../src/connection.js";
import {
    QuicFrameType,
    EMPTY_CONNECTION_ID,
    LongPacketType,
    type QuicFrame,
    type QuicTransportParameters,
} from "../src/types.js";
import { serializeFrame, readFrames } from "../src/frame/frame.js";
import { serializeShortHeader, serializeLongHeader } from "../src/packet/packet.js";
import { concatAll } from "../src/utils.js";
import { createFakeDatagramPair, LOCAL_ADDR, PEER_ADDR } from "./fake-transport.js";

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
