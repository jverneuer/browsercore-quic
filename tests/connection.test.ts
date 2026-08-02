/**
 * Connection integration tests for @browsercore/quic.
 *
 * Drives a real `QuicConnectionImpl` over a fake datagram pair: a client
 * connection and a scripted peer exchange datagrams. Because the TLS handshake
 * and packet protection are out of scope, these tests move *unprotected* frames
 * — enough to verify the read loop, stream open/accept, and frame dispatch.
 */

import { describe, it, expect, afterAll } from "vitest";
import { connectQuic } from "../src/connection.js";
import { QuicFrameType } from "../src/types.js";
import { serializeFrame } from "../src/frame/frame.js";
import { serializeShortHeader } from "../src/packet/packet.js";
import { concatAll } from "../src/utils.js";
import { createFakeDatagramPair, PEER_ADDR } from "./fake-transport.js";

/** Wrap unprotected frames in a short-header 1-RTT packet. */
function makePacket(frames: ReturnType<typeof serializeFrame>[]): Uint8Array {
    const payload = concatAll(frames);
    const dcid = new Uint8Array([0x01, 0x02, 0x03]);
    const header = serializeShortHeader(dcid, 1, false, false);
    const packetNumber = new Uint8Array([0]);
    return concatAll([header, packetNumber, payload]);
}

/** Give the event loop a few ticks to let the read loop process datagrams. */
const tick = (ms = 5) => new Promise<void>((resolve) => setTimeout(resolve, ms));

describe("connectQuic", () => {
    it("returns a connection with an id and open streams", async () => {
        const { client, server } = createFakeDatagramPair();
        const conn = await connectQuic({
            transport: client,
            peer: PEER_ADDR,
            serverName: "localhost",
            initialDcid: new Uint8Array([0x01, 0x02, 0x03]),
            initialScid: new Uint8Array([0x04, 0x05]),
        });

        expect(conn.id.startsWith("quic_")).toBe(true);

        const stream = await conn.openBidirectionalStream();
        expect(stream.id).toBe(0n);

        await conn.close(0x00n, "done");
        await tick();
        void server;
    });

    it("accepts a peer-opened bidirectional stream", async () => {
        const { client, server } = createFakeDatagramPair();
        const conn = await connectQuic({
            transport: client,
            peer: PEER_ADDR,
            serverName: "localhost",
            initialDcid: new Uint8Array([0x01, 0x02, 0x03]),
            initialScid: new Uint8Array([0x04, 0x05]),
        });

        // Peer opens a server-initiated bidirectional stream (id 1) by sending
        // a STREAM frame. Client-initiated bidi streams are even (0, 4, 8…);
        // server-initiated bidi streams are odd (1, 5, 9…).
        const streamFrame = serializeFrame({
            type: QuicFrameType.STREAM,
            streamId: 1n,
            offset: 0n,
            data: new Uint8Array([0xca, 0xfe]),
            fin: true,
        });
        await server.send(makePacket([streamFrame]), PEER_ADDR);
        await tick();

        const accepted = await conn.acceptBidirectionalStream();
        expect(accepted.id).toBe(1n);

        const chunk = await accepted.read();
        expect(Array.from(chunk)).toEqual([0xca, 0xfe]);

        await conn.close(0x00n, "done");
        await tick();
    });

    it("dispatches a CONNECTION_CLOSE from the peer", async () => {
        const { client, server } = createFakeDatagramPair();
        const conn = await connectQuic({
            transport: client,
            peer: PEER_ADDR,
            serverName: "localhost",
            initialDcid: new Uint8Array([0x01, 0x02, 0x03]),
            initialScid: new Uint8Array([0x04, 0x05]),
        });

        const closeFrame = serializeFrame({
            type: QuicFrameType.CONNECTION_CLOSE,
            errorCode: 0x00n,
            frameType: undefined,
            reason: "bye",
        });
        await server.send(makePacket([closeFrame]), PEER_ADDR);
        await tick();

        // After a peer close, opening a new stream must reject.
        await expect(conn.openBidirectionalStream()).rejects.toThrow(/closing/);
    });
});
