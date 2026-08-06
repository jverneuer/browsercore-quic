/**
 * Targeted branch-coverage tests for src/frame/frame.ts.
 *
 * Focuses on the remaining uncovered branches that frame-codec.test.ts
 * doesn't hit:
 *   - ACK_ECN frame with ackRangeCount > 0 (the ack-range parsing loop body)
 *   - Truncated readBytes path (fill(n) returning false inside readBytes)
 *   - STREAM decode for the 0x08/0x09/0x0b/0x0c/0x0d type bytes
 *     (serializer always sets LEN_BIT, but the decoder accepts all 8)
 *   - Additional edge cases for MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS,
 *     DATA_BLOCKED, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID,
 *     PATH_CHALLENGE/PATH_RESPONSE, and CRYPTO frames.
 */

import { describe, it, expect } from "vitest";
import { serializeFrame, decodeFrame, readFrames } from "../src/frame/frame.js";
import { decodeVarint, encodeVarint } from "../src/frame/varint.js";
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

// ---------------------------------------------------------------------------
// ACK_ECN with ack ranges (covers the for-loop body at lines 299-302)
// ---------------------------------------------------------------------------

describe("ACK_ECN with non-zero ackRangeCount", () => {
    it("round-trips an ACK_ECN frame with one ack range", async () => {
        const decoded = await firstFrame({
            type: QuicFrameType.ACK_ECN,
            largestAck: 50n,
            ackDelay: 2n,
            ackRangeCount: 1n,
            firstAckRange: 10n,
            ackRanges: [{ gap: 3n, ackRangeLength: 5n }],
            ecnCounts: { ect0: 7n, ect1: 0n, ce: 1n },
        });
        expect(decoded.type).toBe(QuicFrameType.ACK_ECN);
        if (decoded.type !== QuicFrameType.ACK_ECN) throw new Error("expected ACK_ECN");
        expect(decoded.largestAck).toBe(50n);
        expect(decoded.ackRangeCount).toBe(1n);
        expect(decoded.firstAckRange).toBe(10n);
        expect(decoded.ackRanges).toEqual([{ gap: 3n, ackRangeLength: 5n }]);
        expect(decoded.ecnCounts).toEqual({ ect0: 7n, ect1: 0n, ce: 1n });
    });

    it("round-trips an ACK_ECN frame with multiple ack ranges", async () => {
        const decoded = await firstFrame({
            type: QuicFrameType.ACK_ECN,
            largestAck: 1000n,
            ackDelay: 4n,
            ackRangeCount: 3n,
            firstAckRange: 50n,
            ackRanges: [
                { gap: 1n, ackRangeLength: 2n },
                { gap: 0n, ackRangeLength: 10n },
                { gap: 5n, ackRangeLength: 1n },
            ],
            ecnCounts: { ect0: 100n, ect1: 200n, ce: 50n },
        });
        expect(decoded.type).toBe(QuicFrameType.ACK_ECN);
        if (decoded.type !== QuicFrameType.ACK_ECN) throw new Error("expected ACK_ECN");
        expect(decoded.ackRangeCount).toBe(3n);
        expect(decoded.ackRanges).toHaveLength(3);
        expect(decoded.ackRanges).toEqual([
            { gap: 1n, ackRangeLength: 2n },
            { gap: 0n, ackRangeLength: 10n },
            { gap: 5n, ackRangeLength: 1n },
        ]);
    });

    it("round-trips an ACK_ECN with ranges but no ecnCounts (falls back to ACK)", async () => {
        const bytes = serializeFrame({
            type: QuicFrameType.ACK_ECN,
            largestAck: 20n,
            ackDelay: 0n,
            ackRangeCount: 1n,
            firstAckRange: 5n,
            ackRanges: [{ gap: 0n, ackRangeLength: 3n }],
        });
        // ecnCounts omitted → serializer emits a plain ACK (type 0x02).
        expect(bytes[0]).toBe(QuicFrameType.ACK);
        const [decoded] = await decodeAll(bytes);
        expect(decoded?.type).toBe(QuicFrameType.ACK);
    });
});

// ---------------------------------------------------------------------------
// Truncated readBytes (covers line 228 — fill(n) returns false in readBytes)
// ---------------------------------------------------------------------------

describe("truncated readBytes path", () => {
    it("throws when a CRYPTO frame declares more data bytes than are available", async () => {
        // Build: CRYPTO type (0x06) + offset varint + length varint, then fewer
        // data bytes than declared. The header reads fine; readBytes(length) fails.
        const header = serializeFrame({
            type: QuicFrameType.CRYPTO,
            offset: 0n,
            data: new Uint8Array(10), // declares length = 10
        });
        // Chop off the trailing data bytes — keep only the 3 header bytes
        // (type + offset varint + length varint).
        const truncated = header.subarray(0, 3);
        const read = fullReader(truncated);
        const it = readFrames(read)[Symbol.asyncIterator]();
        await expect(it.next()).rejects.toThrow(/unexpected end of frame data/);
    });

    it("throws when a NEW_TOKEN frame declares a longer token than available", async () => {
        // NEW_TOKEN (0x07) + length varint (= 100), then zero bytes.
        const bytes = new Uint8Array([QuicFrameType.NEW_TOKEN, 100]);
        const read = fullReader(bytes);
        const it = readFrames(read)[Symbol.asyncIterator]();
        await expect(it.next()).rejects.toThrow(/unexpected end of frame data/);
    });

    it("throws when a STREAM frame declares more data than is available", async () => {
        // STREAM base 0x08 | LEN(0x02) = 0x0a, streamId=0, length=50, then 2 bytes.
        const bytes = new Uint8Array([0x0a, 0x00 /* streamId */, 50 /* length */, 0x01, 0x02]);
        const read = fullReader(bytes);
        const it = readFrames(read)[Symbol.asyncIterator]();
        await expect(it.next()).rejects.toThrow(/unexpected end of frame data/);
    });

    it("throws when a CONNECTION_CLOSE reason is truncated", async () => {
        // CONNECTION_CLOSE (0x1c) + errorCode(=1, 1 byte) + frameType(=0, 1 byte)
        // + reasonLength(=100) + 2 bytes of reason.
        const bytes = new Uint8Array([
            0x1c /* CONNECTION_CLOSE */,
            0x01 /* errorCode = 1 */,
            0x00 /* frameType = 0 */,
            100 /* reasonLength */,
            0x41,
            0x42 /* 2 reason bytes */,
        ]);
        const read = fullReader(bytes);
        const it = readFrames(read)[Symbol.asyncIterator]();
        await expect(it.next()).rejects.toThrow(/unexpected end of frame data/);
    });
});

// ---------------------------------------------------------------------------
// STREAM decode for every type byte (0x08..0x0f) — covers all 8 case arms
// ---------------------------------------------------------------------------

describe("STREAM frame decode across all 8 type-byte variants", () => {
    // The serializer always sets LEN_BIT, so only 0x0a/0x0b/0x0e/0x0f are
    // reachable via serializeFrame (all include the length varint). The other
    // four (0x08/0x09/0x0c/0x0d) are exercised via direct decodeFrame calls.
    //
    // The decoder reads: streamId, then offset (only if OFF bit set), then
    // length (always), then data, then derives fin from the FIN bit.

    // --- Round-trip variants the serializer can produce (LEN bit always set) ---

    it("round-trips STREAM with type byte 0x0a (offset=0, len, no fin)", async () => {
        const decoded = await firstFrame({
            type: QuicFrameType.STREAM,
            streamId: 0n,
            offset: 0n,
            data: new Uint8Array([1, 2, 3]),
            fin: false,
        });
        if (decoded.type !== QuicFrameType.STREAM) throw new Error("expected STREAM");
        // Re-serialize and confirm the wire type byte.
        expect(Array.from(serializeFrame(decoded))[0]).toBe(0x0a);
    });

    it("round-trips STREAM with type byte 0x0b (offset=0, len, fin)", async () => {
        const decoded = await firstFrame({
            type: QuicFrameType.STREAM,
            streamId: 2n,
            offset: 0n,
            data: new Uint8Array([0xaa]),
            fin: true,
        });
        if (decoded.type !== QuicFrameType.STREAM) throw new Error("expected STREAM");
        expect(Array.from(serializeFrame(decoded))[0]).toBe(0x0b);
        expect(decoded.streamId).toBe(2n);
        expect(decoded.offset).toBe(0n);
        expect(decoded.fin).toBe(true);
        expect(Array.from(decoded.data)).toEqual([0xaa]);
    });

    it("round-trips STREAM with type byte 0x0e (offset>0, len, no fin)", async () => {
        const decoded = await firstFrame({
            type: QuicFrameType.STREAM,
            streamId: 4n,
            offset: 100n,
            data: new Uint8Array([0xcc]),
            fin: false,
        });
        if (decoded.type !== QuicFrameType.STREAM) throw new Error("expected STREAM");
        expect(Array.from(serializeFrame(decoded))[0]).toBe(0x0e);
        expect(decoded.offset).toBe(100n);
        expect(decoded.fin).toBe(false);
    });

    // --- Direct decodeFrame for type bytes the serializer can't produce ---
    // These lack LEN_BIT (0x08/0x09/0x0c/0x0d). The decoder always reads a
    // length varint, so we provide one via a hand-fed readVarint.

    function decodeStreamType(
        typeByte: number,
        streamVars: bigint[],
        data: Uint8Array,
    ): Promise<QuicFrame> {
        let vi = 0;
        const readVarint = async (): Promise<bigint> => {
            const v = streamVars[vi++];
            if (v === undefined) throw new Error("unexpected varint read");
            return v;
        };
        const readBytes = async (n: bigint): Promise<Uint8Array> => {
            expect(n).toBe(BigInt(data.length));
            return data;
        };
        return decodeFrame(BigInt(typeByte), readVarint, readBytes);
    }

    it("decodes type byte 0x08 (no off/len/fin) — offset defaults to 0", async () => {
        const f = await decodeStreamType(
            0x08,
            [1n /* streamId */, 2n /* length (always read) */],
            new Uint8Array([0x11, 0x22]),
        );
        expect(f.type).toBe(QuicFrameType.STREAM);
        if (f.type !== QuicFrameType.STREAM) throw new Error("expected STREAM");
        expect(f.streamId).toBe(1n);
        expect(f.offset).toBe(0n);
        expect(f.fin).toBe(false);
        expect(Array.from(f.data)).toEqual([0x11, 0x22]);
    });

    it("decodes type byte 0x09 (len+fin, no off)", async () => {
        const f = await decodeStreamType(
            0x09,
            [2n /* streamId */, 1n /* length */],
            new Uint8Array([0xbb]),
        );
        expect(f.type).toBe(QuicFrameType.STREAM);
        if (f.type !== QuicFrameType.STREAM) throw new Error("expected STREAM");
        expect(f.streamId).toBe(2n);
        expect(f.offset).toBe(0n);
        expect(f.fin).toBe(true);
        expect(Array.from(f.data)).toEqual([0xbb]);
    });

    it("decodes type byte 0x0c (off only, no len, no fin)", async () => {
        // OFF bit set, no LEN bit. Decoder still reads length varint.
        const f = await decodeStreamType(
            0x0c,
            [5n /* streamId */, 500n /* offset */, 0n /* length */],
            new Uint8Array(0),
        );
        expect(f.type).toBe(QuicFrameType.STREAM);
        if (f.type !== QuicFrameType.STREAM) throw new Error("expected STREAM");
        expect(f.streamId).toBe(5n);
        expect(f.offset).toBe(500n);
        expect(f.fin).toBe(false);
    });

    it("decodes type byte 0x0d (off+fin, no len)", async () => {
        const f = await decodeStreamType(
            0x0d,
            [8n /* streamId */, 3n /* offset */, 0n /* length */],
            new Uint8Array(0),
        );
        expect(f.type).toBe(QuicFrameType.STREAM);
        if (f.type !== QuicFrameType.STREAM) throw new Error("expected STREAM");
        expect(f.streamId).toBe(8n);
        expect(f.offset).toBe(3n);
        expect(f.fin).toBe(true);
    });
});

// ---------------------------------------------------------------------------
// Additional edge cases for flow-control + stream-management frames
// ---------------------------------------------------------------------------

describe("flow-control and blocked frames — edge values", () => {
    it("round-trips MAX_DATA with a u62-max value", async () => {
        const max = (1n << 62n) - 1n;
        const decoded = await firstFrame({ type: QuicFrameType.MAX_DATA, maximum: max });
        expect(decoded).toMatchObject({ maximum: max });
    });

    it("round-trips MAX_STREAM_DATA with maximum values", async () => {
        const max = (1n << 62n) - 1n;
        const decoded = await firstFrame({
            type: QuicFrameType.MAX_STREAM_DATA,
            streamId: max,
            maximum: max,
        });
        if (decoded.type !== QuicFrameType.MAX_STREAM_DATA) throw new Error("expected MAX_STREAM_DATA");
        expect(decoded.streamId).toBe(max);
        expect(decoded.maximum).toBe(max);
    });

    it("round-trips MAX_STREAMS_BIDI and MAX_STREAMS_UNI with large counts", async () => {
        const max = (1n << 62n) - 1n;
        const bidi = await firstFrame({ type: QuicFrameType.MAX_STREAMS_BIDI, maximum: max });
        if (bidi.type !== QuicFrameType.MAX_STREAMS_BIDI) throw new Error("expected MAX_STREAMS_BIDI");
        expect(bidi.maximum).toBe(max);
        const uni = await firstFrame({ type: QuicFrameType.MAX_STREAMS_UNI, maximum: max });
        if (uni.type !== QuicFrameType.MAX_STREAMS_UNI) throw new Error("expected MAX_STREAMS_UNI");
        expect(uni.maximum).toBe(max);
    });

    it("round-trips DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED with max limit", async () => {
        const max = (1n << 62n) - 1n;
        expect(await firstFrame({ type: QuicFrameType.DATA_BLOCKED, limit: max })).toMatchObject({
            limit: max,
        });
        expect(
            await firstFrame({ type: QuicFrameType.STREAM_DATA_BLOCKED, streamId: 0n, limit: max }),
        ).toMatchObject({ streamId: 0n, limit: max });
        expect(
            await firstFrame({ type: QuicFrameType.STREAMS_BLOCKED_BIDI, limit: max }),
        ).toMatchObject({ limit: max });
        expect(
            await firstFrame({ type: QuicFrameType.STREAMS_BLOCKED_UNI, limit: max }),
        ).toMatchObject({ limit: max });
    });
});

// ---------------------------------------------------------------------------
// NEW_CONNECTION_ID edge cases
// ---------------------------------------------------------------------------

describe("NEW_CONNECTION_ID edge cases", () => {
    it("round-trips with a zero-length connection id", async () => {
        const token = new Uint8Array(16).fill(0xff);
        const decoded = await firstFrame({
            type: QuicFrameType.NEW_CONNECTION_ID,
            sequenceNumber: 0n,
            retirePriorTo: 0n,
            connectionId: new Uint8Array(0),
            statelessResetToken: token,
        });
        if (decoded.type !== QuicFrameType.NEW_CONNECTION_ID)
            throw new Error("expected NEW_CONNECTION_ID");
        expect(Array.from(decoded.connectionId)).toEqual([]);
        expect(decoded.sequenceNumber).toBe(0n);
        expect(decoded.retirePriorTo).toBe(0n);
    });

    it("round-trips with retirePriorTo > sequenceNumber (allowed by the wire format)", async () => {
        const cid = new Uint8Array([0x01, 0x02, 0x03]);
        const token = new Uint8Array(16).fill(0x00);
        const decoded = await firstFrame({
            type: QuicFrameType.NEW_CONNECTION_ID,
            sequenceNumber: 5n,
            retirePriorTo: 10n,
            connectionId: cid,
            statelessResetToken: token,
        });
        if (decoded.type !== QuicFrameType.NEW_CONNECTION_ID)
            throw new Error("expected NEW_CONNECTION_ID");
        expect(decoded.sequenceNumber).toBe(5n);
        expect(decoded.retirePriorTo).toBe(10n);
    });

    it("round-trips with a long connection id (20 bytes) and max sequence", async () => {
        const cid = new Uint8Array(20).fill(0xca);
        const token = new Uint8Array(16).fill(0xac);
        const decoded = await firstFrame({
            type: QuicFrameType.NEW_CONNECTION_ID,
            sequenceNumber: (1n << 62n) - 1n,
            retirePriorTo: 0n,
            connectionId: cid,
            statelessResetToken: token,
        });
        if (decoded.type !== QuicFrameType.NEW_CONNECTION_ID)
            throw new Error("expected NEW_CONNECTION_ID");
        expect(Array.from(decoded.connectionId)).toEqual([...cid]);
        expect(decoded.sequenceNumber).toBe((1n << 62n) - 1n);
    });
});

// ---------------------------------------------------------------------------
// RETIRE_CONNECTION_ID edge cases
// ---------------------------------------------------------------------------

describe("RETIRE_CONNECTION_ID edge cases", () => {
    it("round-trips with sequence number 0", async () => {
        const decoded = await firstFrame({
            type: QuicFrameType.RETIRE_CONNECTION_ID,
            sequenceNumber: 0n,
        });
        expect(decoded).toMatchObject({ sequenceNumber: 0n });
    });

    it("round-trips with a large sequence number", async () => {
        const max = (1n << 62n) - 1n;
        const decoded = await firstFrame({
            type: QuicFrameType.RETIRE_CONNECTION_ID,
            sequenceNumber: max,
        });
        if (decoded.type !== QuicFrameType.RETIRE_CONNECTION_ID)
            throw new Error("expected RETIRE_CONNECTION_ID");
        expect(decoded.sequenceNumber).toBe(max);
    });
});

// ---------------------------------------------------------------------------
// PATH_CHALLENGE / PATH_RESPONSE edge cases
// ---------------------------------------------------------------------------

describe("PATH_CHALLENGE / PATH_RESPONSE edge cases", () => {
    it("round-trips PATH_CHALLENGE delivered in tiny chunks (incremental fill)", async () => {
        const data = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        const bytes = serializeFrame({ type: QuicFrameType.PATH_CHALLENGE, data });
        const out: QuicFrame[] = [];
        for await (const f of readFrames(chunkedReader(bytes, 3))) out.push(f);
        expect(out).toHaveLength(1);
        if (out[0]?.type !== QuicFrameType.PATH_CHALLENGE) throw new Error("expected PATH_CHALLENGE");
        expect(Array.from(out[0].data)).toEqual([...data]);
    });

    it("round-trips PATH_RESPONSE delivered one byte at a time", async () => {
        const data = new Uint8Array([0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]);
        const bytes = serializeFrame({ type: QuicFrameType.PATH_RESPONSE, data });
        const out: QuicFrame[] = [];
        for await (const f of readFrames(chunkedReader(bytes, 1))) out.push(f);
        expect(out).toHaveLength(1);
        if (out[0]?.type !== QuicFrameType.PATH_RESPONSE) throw new Error("expected PATH_RESPONSE");
        expect(Array.from(out[0].data)).toEqual([...data]);
    });

    it("round-trips PATH_CHALLENGE with all-zero data", async () => {
        const data = new Uint8Array(8);
        const decoded = await firstFrame({ type: QuicFrameType.PATH_CHALLENGE, data });
        expect(Array.from(decoded.data)).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
    });
});

// ---------------------------------------------------------------------------
// CRYPTO frame edge cases
// ---------------------------------------------------------------------------

describe("CRYPTO frame edge cases", () => {
    it("round-trips a CRYPTO frame with empty data", async () => {
        const decoded = await firstFrame({
            type: QuicFrameType.CRYPTO,
            offset: 0n,
            data: new Uint8Array(0),
        });
        expect(decoded.type).toBe(QuicFrameType.CRYPTO);
        if (decoded.type !== QuicFrameType.CRYPTO) throw new Error("expected CRYPTO");
        expect(decoded.offset).toBe(0n);
        expect(Array.from(decoded.data)).toEqual([]);
    });

    it("round-trips a CRYPTO frame with large offset", async () => {
        const max = (1n << 62n) - 1n;
        const decoded = await firstFrame({
            type: QuicFrameType.CRYPTO,
            offset: max,
            data: new Uint8Array([0x01]),
        });
        if (decoded.type !== QuicFrameType.CRYPTO) throw new Error("expected CRYPTO");
        expect(decoded.offset).toBe(max);
    });

    it("round-trips a CRYPTO frame with data delivered in chunks", async () => {
        const data = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]);
        const bytes = serializeFrame({ type: QuicFrameType.CRYPTO, offset: 100n, data });
        const out: QuicFrame[] = [];
        for await (const f of readFrames(chunkedReader(bytes, 2))) out.push(f);
        expect(out).toHaveLength(1);
        if (out[0]?.type !== QuicFrameType.CRYPTO) throw new Error("expected CRYPTO");
        expect(out[0]).toMatchObject({ offset: 100n });
        expect(Array.from(out[0].data)).toEqual([...data]);
    });
});

// ---------------------------------------------------------------------------
// CONNECTION_CLOSE variants
// ---------------------------------------------------------------------------

describe("CONNECTION_CLOSE_APP edge cases", () => {
    it("round-trips CONNECTION_CLOSE_APP with no frameType and empty reason", async () => {
        const decoded = await firstFrame({
            type: QuicFrameType.CONNECTION_CLOSE_APP,
            errorCode: 0x42n,
            frameType: undefined,
            reason: "",
        });
        expect(decoded.type).toBe(QuicFrameType.CONNECTION_CLOSE_APP);
        if (decoded.type !== QuicFrameType.CONNECTION_CLOSE_APP)
            throw new Error("expected CONNECTION_CLOSE_APP");
        expect(decoded.errorCode).toBe(0x42n);
        expect(decoded.frameType).toBe(0n);
        expect(decoded.reason).toBe("");
    });

    it("round-trips CONNECTION_CLOSE with a large error code and multi-byte frame type", async () => {
        const max = (1n << 62n) - 1n;
        const decoded = await firstFrame({
            type: QuicFrameType.CONNECTION_CLOSE,
            errorCode: max,
            frameType: max,
            reason: "max values",
        });
        if (decoded.type !== QuicFrameType.CONNECTION_CLOSE)
            throw new Error("expected CONNECTION_CLOSE");
        expect(decoded.errorCode).toBe(max);
        expect(decoded.frameType).toBe(max);
        expect(decoded.reason).toBe("max values");
    });
});

// ---------------------------------------------------------------------------
// ACK frame with multiple ranges via incremental/chunked delivery
// ---------------------------------------------------------------------------

describe("ACK frame with ranges via incremental delivery", () => {
    it("parses an ACK with 3 ack ranges when delivered in 3-byte chunks", async () => {
        const frame = {
            type: QuicFrameType.ACK as const,
            largestAck: 200n,
            ackDelay: 1n,
            ackRangeCount: 3n,
            firstAckRange: 50n,
            ackRanges: [
                { gap: 2n, ackRangeLength: 5n },
                { gap: 1n, ackRangeLength: 3n },
                { gap: 0n, ackRangeLength: 10n },
            ],
        };
        const bytes = serializeFrame(frame);
        const out: QuicFrame[] = [];
        for await (const f of readFrames(chunkedReader(bytes, 3))) out.push(f);
        expect(out).toHaveLength(1);
        if (out[0]?.type !== QuicFrameType.ACK) throw new Error("expected ACK");
        expect(out[0]).toMatchObject({
            largestAck: 200n,
            ackDelay: 1n,
            ackRangeCount: 3n,
            firstAckRange: 50n,
        });
        expect(out[0].ackRanges).toEqual(frame.ackRanges);
    });
});

// ---------------------------------------------------------------------------
// Multi-frame packets mixing several frame types
// ---------------------------------------------------------------------------

describe("mixed multi-frame packets", () => {
    it("parses a packet containing one of each major frame type", async () => {
        const frames: QuicFrame[] = [
            { type: QuicFrameType.PADDING },
            { type: QuicFrameType.PING },
            { type: QuicFrameType.MAX_DATA, maximum: 1000n },
            { type: QuicFrameType.MAX_STREAM_DATA, streamId: 4n, maximum: 500n },
            { type: QuicFrameType.MAX_STREAMS_BIDI, maximum: 10n },
            { type: QuicFrameType.MAX_STREAMS_UNI, maximum: 5n },
            { type: QuicFrameType.DATA_BLOCKED, limit: 2000n },
            { type: QuicFrameType.STREAM_DATA_BLOCKED, streamId: 8n, limit: 100n },
            { type: QuicFrameType.STREAMS_BLOCKED_BIDI, limit: 3n },
            { type: QuicFrameType.STREAMS_BLOCKED_UNI, limit: 1n },
            {
                type: QuicFrameType.NEW_CONNECTION_ID,
                sequenceNumber: 1n,
                retirePriorTo: 0n,
                connectionId: new Uint8Array([0xab, 0xcd]),
                statelessResetToken: new Uint8Array(16).fill(0x11),
            },
            { type: QuicFrameType.RETIRE_CONNECTION_ID, sequenceNumber: 2n },
            { type: QuicFrameType.PATH_CHALLENGE, data: new Uint8Array(8).fill(0x42) },
            { type: QuicFrameType.PATH_RESPONSE, data: new Uint8Array(8).fill(0x24) },
            { type: QuicFrameType.HANDSHAKE_DONE },
        ];
        // Concatenate all serialized frames.
        const pieces = frames.map((f) => serializeFrame(f));
        let total = 0;
        for (const p of pieces) total += p.length;
        const packet = new Uint8Array(total);
        let pos = 0;
        for (const p of pieces) {
            packet.set(p, pos);
            pos += p.length;
        }
        const decoded = await decodeAll(packet);
        expect(decoded).toHaveLength(frames.length);
        const types = decoded.map((f) => f.type);
        expect(types).toEqual([
            QuicFrameType.PADDING,
            QuicFrameType.PING,
            QuicFrameType.MAX_DATA,
            QuicFrameType.MAX_STREAM_DATA,
            QuicFrameType.MAX_STREAMS_BIDI,
            QuicFrameType.MAX_STREAMS_UNI,
            QuicFrameType.DATA_BLOCKED,
            QuicFrameType.STREAM_DATA_BLOCKED,
            QuicFrameType.STREAMS_BLOCKED_BIDI,
            QuicFrameType.STREAMS_BLOCKED_UNI,
            QuicFrameType.NEW_CONNECTION_ID,
            QuicFrameType.RETIRE_CONNECTION_ID,
            QuicFrameType.PATH_CHALLENGE,
            QuicFrameType.PATH_RESPONSE,
            QuicFrameType.HANDSHAKE_DONE,
        ]);
    });
});

// ---------------------------------------------------------------------------
// decodeFrame direct tests for non-standard type-byte inputs
// ---------------------------------------------------------------------------

describe("decodeFrame directly with hand-built bytes", () => {
    it("decodes an ACK_ECN with ack ranges byte-by-byte via manual varints", async () => {
        // ACK_ECN type = 0x03. Provide all varints + ECN counts manually.
        // largestAck=5, ackDelay=0, ackRangeCount=2, firstAckRange=10,
        // gap=1/ackRangeLength=2, gap=3/ackRangeLength=4,
        // ect0=0, ect1=0, ce=0.
        const vars = [5n, 0n, 2n, 10n, 1n, 2n, 3n, 4n, 0n, 0n, 0n];
        let vi = 0;
        const readVarint = async (): Promise<bigint> => vars[vi++]!;
        const readBytes = async (_n: bigint): Promise<Uint8Array> => new Uint8Array(0);
        const f = await decodeFrame(BigInt(QuicFrameType.ACK_ECN), readVarint, readBytes);
        expect(f.type).toBe(QuicFrameType.ACK_ECN);
        if (f.type !== QuicFrameType.ACK_ECN) throw new Error("expected ACK_ECN");
        expect(f.ackRangeCount).toBe(2n);
        expect(f.ackRanges).toEqual([
            { gap: 1n, ackRangeLength: 2n },
            { gap: 3n, ackRangeLength: 4n },
        ]);
        expect(f.ecnCounts).toEqual({ ect0: 0n, ect1: 0n, ce: 0n });
    });

    it("decodes a CONNECTION_CLOSE_APP frame with the type-byte discrimination branch", async () => {
        // CONNECTION_CLOSE_APP (0x1d) hits the other arm of the ternary.
        const vars = [0x01n /* errorCode */, 0x02n /* frameType */, 0x03n /* reasonLength */];
        let vi = 0;
        const readVarint = async (): Promise<bigint> => vars[vi++]!;
        const readBytes = async (_n: bigint): Promise<Uint8Array> => new Uint8Array([0x61, 0x62, 0x63]);
        const f = await decodeFrame(BigInt(QuicFrameType.CONNECTION_CLOSE_APP), readVarint, readBytes);
        expect(f.type).toBe(QuicFrameType.CONNECTION_CLOSE_APP);
        if (f.type !== QuicFrameType.CONNECTION_CLOSE_APP)
            throw new Error("expected CONNECTION_CLOSE_APP");
        expect(f.errorCode).toBe(0x01n);
        expect(f.frameType).toBe(0x02n);
        expect(f.reason).toBe("abc");
    });

    it("decodes a RESET_STREAM with large stream id and error code", async () => {
        const vars = [99n /* streamId */, 0xffn /* errorCode */, 1000n /* finalSize */];
        let vi = 0;
        const readVarint = async (): Promise<bigint> => vars[vi++]!;
        const readBytes = async (_n: bigint): Promise<Uint8Array> => new Uint8Array(0);
        const f = await decodeFrame(BigInt(QuicFrameType.RESET_STREAM), readVarint, readBytes);
        expect(f.type).toBe(QuicFrameType.RESET_STREAM);
        if (f.type !== QuicFrameType.RESET_STREAM) throw new Error("expected RESET_STREAM");
        expect(f.streamId).toBe(99n);
        expect(f.errorCode).toBe(0xffn);
        expect(f.finalSize).toBe(1000n);
    });

    it("decodes a STOP_SENDING frame", async () => {
        const vars = [4n /* streamId */, 0x7n /* errorCode */];
        let vi = 0;
        const readVarint = async (): Promise<bigint> => vars[vi++]!;
        const readBytes = async (_n: bigint): Promise<Uint8Array> => new Uint8Array(0);
        const f = await decodeFrame(BigInt(QuicFrameType.STOP_SENDING), readVarint, readBytes);
        expect(f.type).toBe(QuicFrameType.STOP_SENDING);
        if (f.type !== QuicFrameType.STOP_SENDING) throw new Error("expected STOP_SENDING");
        expect(f.streamId).toBe(4n);
        expect(f.errorCode).toBe(0x7n);
    });

    it("decodes a NEW_CONNECTION_ID from raw bytes", async () => {
        // sequenceNumber=7, retirePriorTo=2, length=4, 4 cid bytes, 16 token bytes.
        const vars = [7n, 2n, 4n];
        let vi = 0;
        const readVarint = async (): Promise<bigint> => vars[vi++]!;
        const readBytes = async (n: bigint): Promise<Uint8Array> => {
            if (n === 4n) return new Uint8Array([0x10, 0x11, 0x12, 0x13]);
            if (n === 16n) return new Uint8Array(16).fill(0xee);
            return new Uint8Array(0);
        };
        const f = await decodeFrame(BigInt(QuicFrameType.NEW_CONNECTION_ID), readVarint, readBytes);
        expect(f.type).toBe(QuicFrameType.NEW_CONNECTION_ID);
        if (f.type !== QuicFrameType.NEW_CONNECTION_ID)
            throw new Error("expected NEW_CONNECTION_ID");
        expect(f.sequenceNumber).toBe(7n);
        expect(f.retirePriorTo).toBe(2n);
        expect(Array.from(f.connectionId)).toEqual([0x10, 0x11, 0x12, 0x13]);
        expect(Array.from(f.statelessResetToken)).toEqual([...new Uint8Array(16).fill(0xee)]);
    });
});
