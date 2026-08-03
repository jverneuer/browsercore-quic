/**
 * Frame codec tests for @browsercore/quic.
 *
 * Exercises serializeFrame + decodeFrame + readFrames for every frame type,
 * including round-trips, the incremental (chunked) read path, multi-frame
 * packets, the exhaustiveness guards, and truncated/malformed input errors.
 */

import { describe, it, expect } from "vitest";
import { serializeFrame, decodeFrame, readFrames } from "../src/frame/frame.js";
import { QuicFrameType, type QuicFrame } from "../src/types.js";

/** A reader that yields the whole buffer once, then null forever. */
function fullReader(bytes: Uint8Array): () => Promise<Uint8Array | null> {
    let done = false;
    return () => {
        if (done) return Promise.resolve(null);
        done = true;
        return Promise.resolve(bytes);
    };
}

/** A reader that yields the buffer in fixed-size slices, then null. */
function chunkedReader(bytes: Uint8Array, size: number): () => Promise<Uint8Array | null> {
    let pos = 0;
    return () => {
        if (pos >= bytes.length) return Promise.resolve(null);
        const chunk = bytes.subarray(pos, pos + size);
        pos += size;
        return Promise.resolve(chunk);
    };
}

async function decodeAll(bytes: Uint8Array): Promise<QuicFrame[]> {
    const out: QuicFrame[] = [];
    for await (const f of readFrames(fullReader(bytes))) out.push(f);
    return out;
}

async function firstFrame(frame: QuicFrame): Promise<QuicFrame> {
    const [f] = await decodeAll(serializeFrame(frame));
    if (f === undefined) throw new Error("no frame decoded");
    return f;
}

describe("serializeFrame + decodeFrame round-trip", () => {
    it("round-trips PADDING and PING (single-byte frames)", async () => {
        expect((await firstFrame({ type: QuicFrameType.PADDING })).type).toBe(QuicFrameType.PADDING);
        expect((await firstFrame({ type: QuicFrameType.PING })).type).toBe(QuicFrameType.PING);
        // The single-byte wire form is exactly the type byte.
        expect(Array.from(serializeFrame({ type: QuicFrameType.PING }))).toEqual([QuicFrameType.PING]);
    });

    it("round-trips a basic ACK frame with ack ranges", async () => {
        const frame = {
            type: QuicFrameType.ACK as const,
            largestAck: 100n,
            ackDelay: 5n,
            ackRangeCount: 2n,
            firstAckRange: 3n,
            ackRanges: [
                { gap: 1n, ackRangeLength: 2n },
                { gap: 4n, ackRangeLength: 6n },
            ],
        };
        const decoded = await firstFrame(frame);
        expect(decoded.type).toBe(QuicFrameType.ACK);
        expect(decoded).toMatchObject({
            largestAck: 100n,
            ackDelay: 5n,
            ackRangeCount: 2n,
            firstAckRange: 3n,
        });
        expect(decoded.ackRanges).toEqual(frame.ackRanges);
    });

    it("round-trips an ACK frame with zero ack ranges", async () => {
        const decoded = await firstFrame({
            type: QuicFrameType.ACK,
            largestAck: 0n,
            ackDelay: 0n,
            ackRangeCount: 0n,
            firstAckRange: 0n,
            ackRanges: [],
        });
        expect(decoded.ackRanges).toEqual([]);
    });

    it("round-trips an ACK_ECN frame including ECN counts", async () => {
        const decoded = await firstFrame({
            type: QuicFrameType.ACK_ECN,
            largestAck: 7n,
            ackDelay: 0n,
            ackRangeCount: 0n,
            firstAckRange: 7n,
            ackRanges: [],
            ecnCounts: { ect0: 1n, ect1: 2n, ce: 3n },
        });
        expect(decoded.type).toBe(QuicFrameType.ACK_ECN);
        expect(decoded.ecnCounts).toEqual({ ect0: 1n, ect1: 2n, ce: 3n });
    });

    it("serializes an ACK_ECN frame without ecnCounts as a plain ACK (type 0x02)", async () => {
        const bytes = serializeFrame({
            type: QuicFrameType.ACK_ECN,
            largestAck: 1n,
            ackDelay: 0n,
            ackRangeCount: 0n,
            firstAckRange: 1n,
            ackRanges: [],
        });
        // First byte is the type varint; falls back to 0x02 (plain ACK) on the wire.
        expect(bytes[0]).toBe(QuicFrameType.ACK);
        const [decoded] = await decodeAll(bytes);
        expect(decoded?.type).toBe(QuicFrameType.ACK);
        expect(decoded?.ecnCounts).toBeUndefined();
    });

    it("round-trips RESET_STREAM and STOP_SENDING", async () => {
        const reset = await firstFrame({
            type: QuicFrameType.RESET_STREAM,
            streamId: 9n,
            errorCode: 0x0cn,
            finalSize: 42n,
        });
        expect(reset).toMatchObject({ streamId: 9n, errorCode: 0x0cn, finalSize: 42n });

        const stop = await firstFrame({
            type: QuicFrameType.STOP_SENDING,
            streamId: 9n,
            errorCode: 0x07n,
        });
        expect(stop).toMatchObject({ streamId: 9n, errorCode: 0x07n });
    });

    it("round-trips a CRYPTO frame carrying payload bytes", async () => {
        const data = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
        const decoded = await firstFrame({
            type: QuicFrameType.CRYPTO,
            offset: 0n,
            data,
        });
        expect(decoded.type).toBe(QuicFrameType.CRYPTO);
        expect(decoded.offset).toBe(0n);
        expect(Array.from(decoded.data)).toEqual([0xde, 0xad, 0xbe, 0xef]);
    });

    it("round-trips a CRYPTO frame with a non-zero offset", async () => {
        const decoded = await firstFrame({
            type: QuicFrameType.CRYPTO,
            offset: 1024n,
            data: new Uint8Array([1, 2]),
        });
        expect(decoded.offset).toBe(1024n);
    });

    it("round-trips a NEW_TOKEN frame", async () => {
        const token = new Uint8Array([1, 2, 3, 4, 5]);
        const decoded = await firstFrame({ type: QuicFrameType.NEW_TOKEN, token });
        expect(Array.from(decoded.token)).toEqual([1, 2, 3, 4, 5]);
    });

    it("round-trips a STREAM frame with offset 0 and no FIN", async () => {
        const decoded = await firstFrame({
            type: QuicFrameType.STREAM,
            streamId: 0n,
            offset: 0n,
            data: new Uint8Array([1, 2, 3]),
            fin: false,
        });
        expect(decoded).toMatchObject({ streamId: 0n, offset: 0n, fin: false });
        expect(Array.from(decoded.data)).toEqual([1, 2, 3]);
    });

    it("round-trips a STREAM frame with a non-zero offset and FIN", async () => {
        // Encodes with the OFF and FIN type-byte bits set.
        const bytes = serializeFrame({
            type: QuicFrameType.STREAM,
            streamId: 4n,
            offset: 100n,
            data: new Uint8Array([9]),
            fin: true,
        });
        // Top type byte should carry STREAM(0x08) | OFF(0x04) | LEN(0x02) | FIN(0x01) = 0x0f.
        expect(bytes[0]).toBe(0x0f);
        const decoded = await firstFrame({
            type: QuicFrameType.STREAM,
            streamId: 4n,
            offset: 100n,
            data: new Uint8Array([9]),
            fin: true,
        });
        expect(decoded).toMatchObject({ streamId: 4n, offset: 100n, fin: true });
    });

    it("round-trips MAX_DATA and MAX_STREAM_DATA", async () => {
        const maxData = await firstFrame({ type: QuicFrameType.MAX_DATA, maximum: 1_048_576n });
        expect(maxData).toMatchObject({ maximum: 1_048_576n });

        const maxStream = await firstFrame({
            type: QuicFrameType.MAX_STREAM_DATA,
            streamId: 8n,
            maximum: 262_144n,
        });
        expect(maxStream).toMatchObject({ streamId: 8n, maximum: 262_144n });
    });

    it("round-trips MAX_STREAMS_BIDI and MAX_STREAMS_UNI", async () => {
        const bidi = await firstFrame({ type: QuicFrameType.MAX_STREAMS_BIDI, maximum: 100n });
        expect(bidi.type).toBe(QuicFrameType.MAX_STREAMS_BIDI);
        expect(bidi).toMatchObject({ maximum: 100n });

        const uni = await firstFrame({ type: QuicFrameType.MAX_STREAMS_UNI, maximum: 50n });
        expect(uni.type).toBe(QuicFrameType.MAX_STREAMS_UNI);
    });

    it("round-trips DATA_BLOCKED, STREAM_DATA_BLOCKED, and STREAMS_BLOCKED_*", async () => {
        expect(await firstFrame({ type: QuicFrameType.DATA_BLOCKED, limit: 1000n })).toMatchObject({
            limit: 1000n,
        });
        expect(
            await firstFrame({ type: QuicFrameType.STREAM_DATA_BLOCKED, streamId: 4n, limit: 10n }),
        ).toMatchObject({ streamId: 4n, limit: 10n });
        expect(
            await firstFrame({ type: QuicFrameType.STREAMS_BLOCKED_BIDI, limit: 7n }),
        ).toMatchObject({ limit: 7n });
        expect(
            await firstFrame({ type: QuicFrameType.STREAMS_BLOCKED_UNI, limit: 3n }),
        ).toMatchObject({ limit: 3n });
    });

    it("round-trips a NEW_CONNECTION_ID frame (stateless reset token is 16 bytes)", async () => {
        const cid = new Uint8Array([0xa0, 0xa1, 0xa2, 0xa3]);
        const token = new Uint8Array(16).fill(0x5a);
        const decoded = await firstFrame({
            type: QuicFrameType.NEW_CONNECTION_ID,
            sequenceNumber: 3n,
            retirePriorTo: 1n,
            connectionId: cid,
            statelessResetToken: token,
        });
        expect(decoded).toMatchObject({ sequenceNumber: 3n, retirePriorTo: 1n });
        expect(Array.from(decoded.connectionId)).toEqual([0xa0, 0xa1, 0xa2, 0xa3]);
        expect(Array.from(decoded.statelessResetToken)).toEqual([...token]);
    });

    it("round-trips RETIRE_CONNECTION_ID", async () => {
        const decoded = await firstFrame({
            type: QuicFrameType.RETIRE_CONNECTION_ID,
            sequenceNumber: 12n,
        });
        expect(decoded).toMatchObject({ sequenceNumber: 12n });
    });

    it("round-trips PATH_CHALLENGE and PATH_RESPONSE (8-byte data)", async () => {
        const challenge = new Uint8Array(8).fill(0xab);
        const decoded = await firstFrame({ type: QuicFrameType.PATH_CHALLENGE, data: challenge });
        expect(Array.from(decoded.data)).toEqual([...challenge]);

        const resp = new Uint8Array(8).fill(0xcd);
        const decodedResp = await firstFrame({ type: QuicFrameType.PATH_RESPONSE, data: resp });
        expect(Array.from(decodedResp.data)).toEqual([...resp]);
    });

    it("round-trips a CONNECTION_CLOSE frame with explicit frameType", async () => {
        const decoded = await firstFrame({
            type: QuicFrameType.CONNECTION_CLOSE,
            errorCode: 0x0cn,
            frameType: 0x10n,
            reason: "flow control",
        });
        expect(decoded).toMatchObject({
            errorCode: 0x0cn,
            frameType: 0x10n,
            reason: "flow control",
        });
    });

    it("encodes a CONNECTION_CLOSE with undefined frameType as 0 on the wire", async () => {
        const decoded = await firstFrame({
            type: QuicFrameType.CONNECTION_CLOSE,
            errorCode: 0n,
            frameType: undefined,
            reason: "",
        });
        // The decoder always surfaces a bigint frameType; undefined serializes as 0n.
        expect(decoded.frameType).toBe(0n);
        expect(decoded.reason).toBe("");
    });

    it("round-trips a CONNECTION_CLOSE_APP frame and a unicode reason phrase", async () => {
        const decoded = await firstFrame({
            type: QuicFrameType.CONNECTION_CLOSE_APP,
            errorCode: 0x0104n,
            frameType: 0n,
            reason: "héllo → 世界",
        });
        expect(decoded.type).toBe(QuicFrameType.CONNECTION_CLOSE_APP);
        expect(decoded.reason).toBe("héllo → 世界");
    });

    it("round-trips HANDSHAKE_DONE", async () => {
        expect((await firstFrame({ type: QuicFrameType.HANDSHAKE_DONE })).type).toBe(
            QuicFrameType.HANDSHAKE_DONE,
        );
        expect(Array.from(serializeFrame({ type: QuicFrameType.HANDSHAKE_DONE }))).toEqual([
            QuicFrameType.HANDSHAKE_DONE,
        ]);
    });
});

describe("readFrames", () => {
    it("parses multiple frames packed into a single packet", async () => {
        const bytes = serializeFrame({ type: QuicFrameType.PING });
        const padding = serializeFrame({ type: QuicFrameType.PADDING });
        const crypto = serializeFrame({
            type: QuicFrameType.CRYPTO,
            offset: 0n,
            data: new Uint8Array([1, 2]),
        });
        // Manually concatenate the three serialized frames.
        const packet = new Uint8Array(bytes.length + padding.length + crypto.length);
        packet.set(bytes, 0);
        packet.set(padding, bytes.length);
        packet.set(crypto, bytes.length + padding.length);

        const frames = await decodeAll(packet);
        expect(frames).toHaveLength(3);
        expect(frames[0]?.type).toBe(QuicFrameType.PING);
        expect(frames[1]?.type).toBe(QuicFrameType.PADDING);
        expect(frames[2]?.type).toBe(QuicFrameType.CRYPTO);
    });

    it("yields no frames for an empty buffer", async () => {
        expect(await decodeAll(new Uint8Array(0))).toEqual([]);
    });

    it("parses frames delivered one byte at a time (incremental fill path)", async () => {
        const bytes = serializeFrame({
            type: QuicFrameType.CRYPTO,
            offset: 10n,
            data: new Uint8Array([1, 2, 3, 4]),
        });
        const out: QuicFrame[] = [];
        for await (const f of readFrames(chunkedReader(bytes, 1))) out.push(f);
        expect(out).toHaveLength(1);
        expect(out[0]?.type).toBe(QuicFrameType.CRYPTO);
        expect(out[0]).toMatchObject({ offset: 10n });
        expect(Array.from(out[0]!.data)).toEqual([1, 2, 3, 4]);
    });

    it("parses frames split across arbitrary 2-byte chunks", async () => {
        const a = serializeFrame({ type: QuicFrameType.PING });
        const b = serializeFrame({
            type: QuicFrameType.MAX_DATA,
            maximum: 1n,
        });
        const packet = new Uint8Array(a.length + b.length);
        packet.set(a, 0);
        packet.set(b, a.length);

        const out: QuicFrame[] = [];
        for await (const f of readFrames(chunkedReader(packet, 2))) out.push(f);
        expect(out.map((f) => f.type)).toEqual([QuicFrameType.PING, QuicFrameType.MAX_DATA]);
    });

    it("throws when a frame is truncated (type present but body missing)", async () => {
        // 0x06 = CRYPTO type; no body bytes follow.
        const read = fullReader(new Uint8Array([0x06]));
        const it = readFrames(read)[Symbol.asyncIterator]();
        await expect(it.next()).rejects.toThrow(/unexpected end of frame data/);
    });

    it("throws when a multi-byte varint type is truncated", async () => {
        // 0x40 => 2-byte varint prefix, but only one byte is available.
        const read = fullReader(new Uint8Array([0x40]));
        const it = readFrames(read)[Symbol.asyncIterator]();
        await expect(it.next()).rejects.toThrow(/unexpected end of frame data/);
    });
});

describe("decodeFrame unknown types", () => {
    it("surfaces a PADDING frame for an unrecognized type value", async () => {
        const noop = async (): Promise<bigint> => 0n;
        const nobytes = async (): Promise<Uint8Array> => new Uint8Array(0);
        const f = await decodeFrame(99n, noop, nobytes);
        expect(f.type).toBe(QuicFrameType.PADDING);
    });

    it("decodes a STREAM family type byte (0x0f: off|len|fin) directly", async () => {
        // Feed streamId=4n, offset=5n, length=2n, then 2 data bytes.
        const vars = [4n, 5n, 2n];
        let vi = 0;
        const readVarint = async (): Promise<bigint> => vars[vi++]!;
        let bytesCalled = false;
        const readBytes = async (_n: bigint): Promise<Uint8Array> => {
            bytesCalled = true;
            return new Uint8Array([1, 2]);
        };
        const f = await decodeFrame(0x0fn, readVarint, readBytes);
        expect(f.type).toBe(QuicFrameType.STREAM);
        expect(f).toMatchObject({ streamId: 4n, offset: 5n, fin: true });
        expect(bytesCalled).toBe(true);
    });

    it("decodes a STREAM type byte without the offset bit (0x0a)", async () => {
        const vars = [8n /* streamId */, 1n /* length */];
        let vi = 0;
        const readVarint = async (): Promise<bigint> => vars[vi++]!;
        const readBytes = async (_n: bigint): Promise<Uint8Array> => new Uint8Array([0x77]);
        const f = await decodeFrame(0x0an, readVarint, readBytes);
        expect(f.type).toBe(QuicFrameType.STREAM);
        expect(f).toMatchObject({ streamId: 8n, offset: 0n, fin: false });
        expect(Array.from(f.data)).toEqual([0x77]);
    });
});

describe("serializeFrame exhaustiveness guard", () => {
    it("throws when given a frame type not in the switch (cast)", () => {
        const bogus = { type: 0xff } as unknown as QuicFrame;
        expect(() => serializeFrame(bogus)).toThrow(/Unexpected value/);
    });
});
