/**
 * Wire-format unit tests for @browsercore/quic.
 *
 * Pure parse/serialize round-trips for varint, QUIC frames, and packet headers.
 * No I/O, no transport — these exercise the deterministic core.
 */

import { describe, it, expect } from "vitest";
import {
    decodeVarint,
    encodeVarint,
    getVarintEncodedLength,
    VARINT_MAX,
} from "../src/frame/varint.js";
import { decodeFrame, readFrames, serializeFrame } from "../src/frame/frame.js";
import {
    parsePacketHeader,
    serializeLongHeader,
    serializeShortHeader,
    decodePacketNumber,
    encodePacketNumber,
    readPacketNumber,
} from "../src/packet/packet.js";
import { QuicFrameType } from "../src/types.js";
import { concatAll } from "../src/utils.js";

// ---------------------------------------------------------------------------
// varint (RFC 9000 §16)
// ---------------------------------------------------------------------------

describe("varint", () => {
    it("encodes 1/2/4/byte forms and round-trips", () => {
        const cases = [0n, 1n, 63n, 64n, 16_383n, 16_384n, 1_073_741_823n, 1_073_741_824n, VARINT_MAX];
        for (const value of cases) {
            const encoded = encodeVarint(value);
            const { value: decoded, length } = decodeVarint(encoded);
            expect(decoded).toBe(value);
            expect(length).toBe(encoded.length);
        }
    });

    it("selects the shortest encoding length", () => {
        expect(getVarintEncodedLength(0n)).toBe(1);
        expect(getVarintEncodedLength(63n)).toBe(1);
        expect(getVarintEncodedLength(64n)).toBe(2);
        expect(getVarintEncodedLength(16_383n)).toBe(2);
        expect(getVarintEncodedLength(16_384n)).toBe(4);
        expect(getVarintEncodedLength(1_073_741_823n)).toBe(4);
        expect(getVarintEncodedLength(1_073_741_824n)).toBe(8);
        expect(getVarintEncodedLength(VARINT_MAX)).toBe(8);
    });

    it("rejects negative and out-of-range values", () => {
        expect(() => encodeVarint(-1n)).toThrow(RangeError);
        expect(() => encodeVarint(VARINT_MAX + 1n)).toThrow(RangeError);
    });

    it("decodes from an offset", () => {
        const encoded = encodeVarint(16_384n);
        const padding = new Uint8Array([0, 0]);
        const buf = concatAll([padding, encoded]);
        const { value, length } = decodeVarint(buf, 2);
        expect(value).toBe(16_384n);
        expect(length).toBe(encoded.length);
    });
});

// ---------------------------------------------------------------------------
// frames — round-trip each type through serializeFrame + decodeFrame
// ---------------------------------------------------------------------------

async function readOneFrame(buf: Uint8Array) {
    let offset = 0;
    const read = async (): Promise<Uint8Array | null> => {
        if (offset >= buf.length) return null;
        const chunk = buf.subarray(offset);
        offset = buf.length;
        return chunk;
    };
    const iterable = readFrames(read);
    const iterator = iterable[Symbol.asyncIterator]();
    const next = await iterator.next();
    expect(next.done).toBe(false);
    return next.value!;
}

describe("frame round-trip", () => {
    it("PADDING", async () => {
        const frame = await readOneFrame(serializeFrame({ type: QuicFrameType.PADDING }));
        expect(frame.type).toBe(QuicFrameType.PADDING);
    });

    it("PING", async () => {
        const frame = await readOneFrame(serializeFrame({ type: QuicFrameType.PING }));
        expect(frame.type).toBe(QuicFrameType.PING);
    });

    it("ACK", async () => {
        const serialized = serializeFrame({
            type: QuicFrameType.ACK,
            largestAck: 100n,
            ackDelay: 5n,
            ackRangeCount: 1n,
            firstAckRange: 10n,
            ackRanges: [{ gap: 1n, ackRangeLength: 2n }],
        });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.ACK);
        if (frame.type !== QuicFrameType.ACK) return;
        expect(frame.largestAck).toBe(100n);
        expect(frame.ackDelay).toBe(5n);
        expect(frame.ackRangeCount).toBe(1n);
        expect(frame.firstAckRange).toBe(10n);
        expect(frame.ackRanges).toEqual([{ gap: 1n, ackRangeLength: 2n }]);
    });

    it("RESET_STREAM", async () => {
        const serialized = serializeFrame({
            type: QuicFrameType.RESET_STREAM,
            streamId: 0n,
            errorCode: 0x01n,
            finalSize: 42n,
        });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.RESET_STREAM);
        if (frame.type !== QuicFrameType.RESET_STREAM) return;
        expect(frame.streamId).toBe(0n);
        expect(frame.errorCode).toBe(0x01n);
        expect(frame.finalSize).toBe(42n);
    });

    it("STOP_SENDING", async () => {
        const serialized = serializeFrame({
            type: QuicFrameType.STOP_SENDING,
            streamId: 4n,
            errorCode: 0x02n,
        });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.STOP_SENDING);
        if (frame.type !== QuicFrameType.STOP_SENDING) return;
        expect(frame.streamId).toBe(4n);
        expect(frame.errorCode).toBe(0x02n);
    });

    it("CRYPTO", async () => {
        const data = new Uint8Array([1, 2, 3, 4, 5]);
        const serialized = serializeFrame({ type: QuicFrameType.CRYPTO, offset: 7n, data });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.CRYPTO);
        if (frame.type !== QuicFrameType.CRYPTO) return;
        expect(frame.offset).toBe(7n);
        expect(Array.from(frame.data)).toEqual([1, 2, 3, 4, 5]);
    });

    it("NEW_TOKEN", async () => {
        const token = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
        const serialized = serializeFrame({ type: QuicFrameType.NEW_TOKEN, token });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.NEW_TOKEN);
        if (frame.type !== QuicFrameType.NEW_TOKEN) return;
        expect(Array.from(frame.token)).toEqual([0xde, 0xad, 0xbe, 0xef]);
    });

    it("STREAM without offset, without fin", async () => {
        const data = new Uint8Array([0xa, 0xb]);
        const serialized = serializeFrame({ type: QuicFrameType.STREAM, streamId: 0n, offset: 0n, data, fin: false });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.STREAM);
        if (frame.type !== QuicFrameType.STREAM) return;
        expect(frame.streamId).toBe(0n);
        expect(frame.offset).toBe(0n);
        expect(Array.from(frame.data)).toEqual([0xa, 0xb]);
        expect(frame.fin).toBe(false);
    });

    it("STREAM with offset and fin", async () => {
        const data = new Uint8Array([0xc]);
        const serialized = serializeFrame({ type: QuicFrameType.STREAM, streamId: 4n, offset: 100n, data, fin: true });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.STREAM);
        if (frame.type !== QuicFrameType.STREAM) return;
        expect(frame.streamId).toBe(4n);
        expect(frame.offset).toBe(100n);
        expect(frame.fin).toBe(true);
    });

    it("MAX_DATA", async () => {
        const serialized = serializeFrame({ type: QuicFrameType.MAX_DATA, maximum: 1_000_000n });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.MAX_DATA);
        if (frame.type !== QuicFrameType.MAX_DATA) return;
        expect(frame.maximum).toBe(1_000_000n);
    });

    it("MAX_STREAM_DATA", async () => {
        const serialized = serializeFrame({ type: QuicFrameType.MAX_STREAM_DATA, streamId: 0n, maximum: 500n });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.MAX_STREAM_DATA);
        if (frame.type !== QuicFrameType.MAX_STREAM_DATA) return;
        expect(frame.streamId).toBe(0n);
        expect(frame.maximum).toBe(500n);
    });

    it("MAX_STREAMS_BIDI", async () => {
        const serialized = serializeFrame({ type: QuicFrameType.MAX_STREAMS_BIDI, maximum: 100n });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.MAX_STREAMS_BIDI);
        if (frame.type !== QuicFrameType.MAX_STREAMS_BIDI) return;
        expect(frame.maximum).toBe(100n);
    });

    it("MAX_STREAMS_UNI", async () => {
        const serialized = serializeFrame({ type: QuicFrameType.MAX_STREAMS_UNI, maximum: 30n });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.MAX_STREAMS_UNI);
        if (frame.type !== QuicFrameType.MAX_STREAMS_UNI) return;
        expect(frame.maximum).toBe(30n);
    });

    it("DATA_BLOCKED", async () => {
        const serialized = serializeFrame({ type: QuicFrameType.DATA_BLOCKED, limit: 1_000n });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.DATA_BLOCKED);
        if (frame.type !== QuicFrameType.DATA_BLOCKED) return;
        expect(frame.limit).toBe(1_000n);
    });

    it("STREAM_DATA_BLOCKED", async () => {
        const serialized = serializeFrame({ type: QuicFrameType.STREAM_DATA_BLOCKED, streamId: 0n, limit: 2_000n });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.STREAM_DATA_BLOCKED);
        if (frame.type !== QuicFrameType.STREAM_DATA_BLOCKED) return;
        expect(frame.limit).toBe(2_000n);
    });

    it("STREAMS_BLOCKED_BIDI", async () => {
        const serialized = serializeFrame({ type: QuicFrameType.STREAMS_BLOCKED_BIDI, limit: 50n });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.STREAMS_BLOCKED_BIDI);
        if (frame.type !== QuicFrameType.STREAMS_BLOCKED_BIDI) return;
        expect(frame.limit).toBe(50n);
    });

    it("NEW_CONNECTION_ID", async () => {
        const connectionId = new Uint8Array([1, 2, 3, 4]);
        const token = new Uint8Array(16).fill(0xab);
        const serialized = serializeFrame({
            type: QuicFrameType.NEW_CONNECTION_ID,
            sequenceNumber: 3n,
            retirePriorTo: 1n,
            connectionId,
            statelessResetToken: token,
        });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.NEW_CONNECTION_ID);
        if (frame.type !== QuicFrameType.NEW_CONNECTION_ID) return;
        expect(frame.sequenceNumber).toBe(3n);
        expect(frame.retirePriorTo).toBe(1n);
        expect(Array.from(frame.connectionId)).toEqual([1, 2, 3, 4]);
        expect(frame.statelessResetToken.length).toBe(16);
    });

    it("RETIRE_CONNECTION_ID", async () => {
        const serialized = serializeFrame({ type: QuicFrameType.RETIRE_CONNECTION_ID, sequenceNumber: 2n });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.RETIRE_CONNECTION_ID);
        if (frame.type !== QuicFrameType.RETIRE_CONNECTION_ID) return;
        expect(frame.sequenceNumber).toBe(2n);
    });

    it("PATH_CHALLENGE", async () => {
        const data = new Uint8Array(8).fill(0x11);
        const serialized = serializeFrame({ type: QuicFrameType.PATH_CHALLENGE, data });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.PATH_CHALLENGE);
        if (frame.type !== QuicFrameType.PATH_CHALLENGE) return;
        expect(frame.data.length).toBe(8);
    });

    it("CONNECTION_CLOSE", async () => {
        const serialized = serializeFrame({
            type: QuicFrameType.CONNECTION_CLOSE,
            errorCode: 0x00n,
            frameType: 0xffn,
            reason: "goaway",
        });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.CONNECTION_CLOSE);
        if (frame.type !== QuicFrameType.CONNECTION_CLOSE) return;
        expect(frame.errorCode).toBe(0x00n);
        expect(frame.reason).toBe("goaway");
    });

    it("HANDSHAKE_DONE", async () => {
        const frame = await readOneFrame(serializeFrame({ type: QuicFrameType.HANDSHAKE_DONE }));
        expect(frame.type).toBe(QuicFrameType.HANDSHAKE_DONE);
    });

    it("ACK_ECN round-trips the ack ranges and ECN counts", async () => {
        const serialized = serializeFrame({
            type: QuicFrameType.ACK_ECN,
            largestAck: 50n,
            ackDelay: 2n,
            ackRangeCount: 1n,
            firstAckRange: 5n,
            ackRanges: [{ gap: 1n, ackRangeLength: 2n }],
            ecnCounts: { ect0: 1n, ect1: 2n, ce: 3n },
        });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.ACK_ECN);
        if (frame.type !== QuicFrameType.ACK_ECN) return;
        expect(frame.ackRanges).toEqual([{ gap: 1n, ackRangeLength: 2n }]);
        expect(frame.ecnCounts).toEqual({ ect0: 1n, ect1: 2n, ce: 3n });
    });

    it("STREAMS_BLOCKED_UNI round-trips", async () => {
        const serialized = serializeFrame({ type: QuicFrameType.STREAMS_BLOCKED_UNI, limit: 7n });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.STREAMS_BLOCKED_UNI);
        if (frame.type !== QuicFrameType.STREAMS_BLOCKED_UNI) return;
        expect(frame.limit).toBe(7n);
    });

    it("PATH_RESPONSE round-trips", async () => {
        const data = new Uint8Array(8).fill(0x22);
        const serialized = serializeFrame({ type: QuicFrameType.PATH_RESPONSE, data });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.PATH_RESPONSE);
        if (frame.type !== QuicFrameType.PATH_RESPONSE) return;
        expect(frame.data.length).toBe(8);
    });

    it("CONNECTION_CLOSE_APP round-trips", async () => {
        const serialized = serializeFrame({
            type: QuicFrameType.CONNECTION_CLOSE_APP,
            errorCode: 0x01n,
            frameType: 0x06n,
            reason: "app",
        });
        const frame = await readOneFrame(serialized);
        expect(frame.type).toBe(QuicFrameType.CONNECTION_CLOSE_APP);
        if (frame.type !== QuicFrameType.CONNECTION_CLOSE_APP) return;
        expect(frame.errorCode).toBe(0x01n);
        expect(frame.reason).toBe("app");
    });
});

describe("readFrames error paths", () => {
    it("throws when a varint is truncated mid-stream", async () => {
        // First byte declares a 2-byte varint (prefix 01) but no follow-up byte.
        const buf = new Uint8Array([0x40]);
        let offset = 0;
        const read = async (): Promise<Uint8Array | null> => {
            if (offset >= buf.length) return null;
            const chunk = buf.subarray(offset);
            offset = buf.length;
            return chunk;
        };
        const iterable = readFrames(read);
        const iterator = iterable[Symbol.asyncIterator]();
        await expect(iterator.next()).rejects.toThrow(/unexpected end of frame data/);
    });

    it("throws when STREAM data is truncated to fewer bytes than declared", async () => {
        // Build a STREAM frame whose length varint says 10 bytes but only 2 follow.
        const serialized = serializeFrame({
            type: QuicFrameType.STREAM,
            streamId: 0n,
            offset: 0n,
            data: new Uint8Array([0x01, 0x02, 0x03]),
            fin: false,
        });
        // Truncate to type + streamid + offset(0) + length varint, then 1 data byte.
        // The length varint (3) is at the end; replace the trailing data with 1 byte.
        const truncated = serialized.subarray(0, serialized.length - 2);
        let offset = 0;
        const read = async (): Promise<Uint8Array | null> => {
            if (offset >= truncated.length) return null;
            const chunk = truncated.subarray(offset);
            offset = truncated.length;
            return chunk;
        };
        const iterable = readFrames(read);
        const iterator = iterable[Symbol.asyncIterator]();
        await expect(iterator.next()).rejects.toThrow(/unexpected end of frame data/);
    });
});

describe("STREAM decode: raw type-byte cases the serializer never emits", () => {
    // The serializer always sets the LEN bit (and OFF when offset>0), so it
    // emits 0x0a/0x0b/0x0e/0x0f. The decoder must still accept the bare
    // 0x08 (no flags) and 0x09 (FIN only) forms a peer could send.

    it("decodes a bare 0x08 STREAM (no offset/fin/len flags)", async () => {
        // type=0x08, streamId=0, length=1, data=0xff
        const buf = new Uint8Array([0x08, 0x00, 0x01, 0xff]);
        const frame = await readOneFrame(buf);
        expect(frame.type).toBe(QuicFrameType.STREAM);
        if (frame.type !== QuicFrameType.STREAM) return;
        expect(frame.offset).toBe(0n);
        expect(frame.fin).toBe(false);
        expect(Array.from(frame.data)).toEqual([0xff]);
    });

    it("decodes a 0x09 STREAM (FIN flag only)", async () => {
        // type=0x09, streamId=0, length=1, data=0xff
        const buf = new Uint8Array([0x09, 0x00, 0x01, 0xff]);
        const frame = await readOneFrame(buf);
        expect(frame.type).toBe(QuicFrameType.STREAM);
        if (frame.type !== QuicFrameType.STREAM) return;
        expect(frame.fin).toBe(true);
    });
});

describe("decodeFrame", () => {
    it("maps an unknown frame type to PADDING (RFC 9000 ignore rule)", async () => {
        // 0xff is not a valid QUIC frame type; the decoder must not throw.
        const readVarint = async (): Promise<bigint> => {
            throw new Error("should not read body");
        };
        const readBytes = async (): Promise<Uint8Array> => new Uint8Array(0);
        const frame = await decodeFrame(0xffn, readVarint, readBytes);
        expect(frame.type).toBe(QuicFrameType.PADDING);
    });
});

describe("serializeFrame", () => {
    it("its exhaustiveness default throws for an unknown frame variant", () => {
        // The discriminated union has no member at type-byte 0x7f; the type
        // system forbids it, so we cast to exercise the assertNever guard.
        const bogus = { type: 0x7f } as unknown as QuicFrame;
        expect(() => serializeFrame(bogus)).toThrow(/Unexpected value/);
    });
});

// ---------------------------------------------------------------------------
// packet header parse/serialize (RFC 9000 §17)
// ---------------------------------------------------------------------------

describe("packet header", () => {
    it("parses a long header back from serializeLongHeader", () => {
        const dcid = new Uint8Array([1, 2, 3, 4]);
        const scid = new Uint8Array([5, 6]);
        const header = serializeLongHeader(0b00, 0x00000001, dcid, scid, 2);
        const parsed = parsePacketHeader(header);
        expect(parsed.form).toBe(1);
        if (parsed.form !== 1) return;
        expect(parsed.version).toBe(0x00000001);
        expect(Array.from(parsed.dcid)).toEqual([1, 2, 3, 4]);
        expect(Array.from(parsed.scid)).toEqual([5, 6]);
        expect(parsed.packetNumberLength).toBe(2);
    });

    it("parses a short header back from serializeShortHeader", () => {
        const dcid = new Uint8Array([9, 8, 7]);
        const header = serializeShortHeader(dcid, 1, true, true);
        const parsed = parsePacketHeader(header);
        expect(parsed.form).toBe(0);
        if (parsed.form !== 0) return;
        expect(parsed.spinBit).toBe(true);
        expect(parsed.keyPhase).toBe(true);
        expect(parsed.packetNumberLength).toBe(1);
    });

    it("decodePacketNumber recovers the truncated value", () => {
        // Largest observed = 0x1234, peer sends the low 16 bits of the next pn.
        const largest = 0x1234n;
        const next = 0x1235n;
        const truncated = encodePacketNumber(next, 16);
        const decoded = decodePacketNumber(largest, truncated, 16);
        expect(decoded).toBe(next);
    });

    it("readPacketNumber reads big-endian bytes", () => {
        const buf = new Uint8Array([0x00, 0x01, 0x02]);
        expect(readPacketNumber(buf, 0, 3)).toBe(0x000102n);
    });

    it("throws when the buffer is empty", () => {
        expect(() => parsePacketHeader(new Uint8Array(0))).toThrow(/too short for packet header/);
    });

    it("throws when a long header is truncated before the minimum length", () => {
        // First byte = long header (form=1), then only 5 bytes (need >=7).
        const buf = new Uint8Array([0xc0, 0x00, 0x00, 0x00, 0x00, 0x00]);
        expect(() => parsePacketHeader(buf)).toThrow(/too short for long header/);
    });

    it("throws when a long header's DCID runs past the buffer end", () => {
        // first=0xc0, version(4 bytes)=0..0, dcidLen=10 => need 6+10+1=17 bytes.
        const buf = new Uint8Array(10);
        buf[0] = 0xc0;
        buf[5] = 10; // dcidLen
        expect(() => parsePacketHeader(buf)).toThrow(/too short for DCID/);
    });

    it("throws when a long header's SCID runs past the buffer end", () => {
        // first=0xc0, version(4), dcidLen=0, scidLen=5 => need 6+0+1+5=12 bytes.
        const buf = new Uint8Array(11);
        buf[0] = 0xc0;
        buf[5] = 0; // dcidLen = 0
        buf[6] = 5; // scidLen = 5
        expect(() => parsePacketHeader(buf)).toThrow(/too short for SCID/);
    });

    it("decodePacketNumber adds pnWin when the candidate is well below the window", () => {
        // expected=98304 (=pnWin+pnHwin); truncated=0 makes candidate=pnWin
        // (65536), which is <= expected-pnHwin (65536) -> +pnWin branch.
        const largest = 98_303n;
        const truncated = 0n;
        const decoded = decodePacketNumber(largest, truncated, 16);
        expect(decoded).toBe(131_072n); // candidate + pnWin
    });

    it("decodePacketNumber subtracts pnWin when the candidate is well above the window", () => {
        // expected=65536; truncated=32769 makes candidate=98305, which is >
        // expected+pnHwin (98304) -> -pnWin branch.
        const largest = 65_535n;
        const truncated = 32_769n;
        const decoded = decodePacketNumber(largest, truncated, 16);
        expect(decoded).toBe(32_769n); // candidate - pnWin
    });
});
