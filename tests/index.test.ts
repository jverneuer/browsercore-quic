/**
 * Public surface test for @browsercore/quic.
 *
 * Imports the package through its barrel (index.ts) to confirm the documented
 * public API is exported and to exercise the barrel module itself.
 */

import { describe, it, expect } from "vitest";
import {
    connectQuic,
    QuicConnectionImpl,
    ConnectionClosedError,
    FlowControlError,
    FrameParseError,
    HandshakeTimeoutError,
    PacketParseError,
    QuicError,
    ResetStreamError,
    StopSendingError,
    TransportParameterError,
    LongPacketType,
    QuicFrameType,
    TransportParameter,
    EMPTY_CONNECTION_ID,
    HEADER_FORM_LONG,
    HEADER_FORM_SHORT,
    MIN_MAX_UDP_PAYLOAD_SIZE,
    STREAM_FIN_BIT,
    STREAM_LEN_BIT,
    STREAM_OFF_BIT,
    firstStreamId,
    makeStreamId,
    nextStreamId,
    streamIdIsBidirectional,
    streamIdIsClientInitiated,
    VARINT_MAX,
    decodeVarint,
    encodeVarint,
    encodeVarintInto,
    getVarintEncodedLength,
    prefixMask,
    decodeFrame,
    readFrames,
    serializeFrame,
    parsePacketHeader,
    serializeShortHeader,
    serializeLongHeader,
    decodePacketNumber,
    encodePacketNumber,
    createStreamManager,
    assertNever,
    concat,
    concatAll,
    hex,
} from "../src/index.js";

describe("barrel public API", () => {
    it("re-exports the connection factory and implementation", () => {
        expect(typeof connectQuic).toBe("function");
        expect(QuicConnectionImpl).toBeDefined();
    });

    it("re-exports every typed error", () => {
        expect(ConnectionClosedError).toBeDefined();
        expect(FlowControlError).toBeDefined();
        expect(FrameParseError).toBeDefined();
        expect(HandshakeTimeoutError).toBeDefined();
        expect(PacketParseError).toBeDefined();
        expect(QuicError).toBeDefined();
        expect(ResetStreamError).toBeDefined();
        expect(StopSendingError).toBeDefined();
        expect(TransportParameterError).toBeDefined();
    });

    it("re-exports enum-like constants and stream-id helpers", () => {
        expect(LongPacketType.INITIAL).toBe(0b00);
        expect(QuicFrameType.STREAM).toBe(0x08);
        expect(TransportParameter.INITIAL_MAX_DATA).toBe(0x04);
        expect(EMPTY_CONNECTION_ID.length).toBe(0);
        expect(HEADER_FORM_LONG).toBe(1);
        expect(HEADER_FORM_SHORT).toBe(0);
        expect(MIN_MAX_UDP_PAYLOAD_SIZE).toBe(1200);
        expect(STREAM_OFF_BIT).toBe(0x04);
        expect(STREAM_LEN_BIT).toBe(0x02);
        expect(STREAM_FIN_BIT).toBe(0x01);
        expect(firstStreamId(true, true)).toBe(0n);
        expect(makeStreamId(5n)).toBe(5n);
        expect(nextStreamId(0n)).toBe(4n);
        expect(streamIdIsBidirectional(0n)).toBe(true);
        expect(streamIdIsClientInitiated(0n)).toBe(true);
    });

    it("re-exports varint helpers", () => {
        expect(VARINT_MAX).toBe((1n << 62n) - 1n);
        expect(typeof decodeVarint).toBe("function");
        expect(typeof encodeVarint).toBe("function");
        expect(typeof encodeVarintInto).toBe("function");
        expect(typeof getVarintEncodedLength).toBe("function");
        expect(typeof prefixMask).toBe("function");
    });

    it("re-exports frame and stream helpers", () => {
        expect(typeof decodeFrame).toBe("function");
        expect(typeof readFrames).toBe("function");
        expect(typeof serializeFrame).toBe("function");
        expect(typeof createStreamManager).toBe("function");
    });

    it("re-exports packet header + packet-number helpers", () => {
        expect(typeof parsePacketHeader).toBe("function");
        expect(typeof serializeShortHeader).toBe("function");
        expect(typeof serializeLongHeader).toBe("function");
        expect(typeof decodePacketNumber).toBe("function");
        expect(typeof encodePacketNumber).toBe("function");
    });

    it("re-exports byte helpers", () => {
        expect(typeof assertNever).toBe("function");
        expect(typeof concat).toBe("function");
        expect(typeof concatAll).toBe("function");
        expect(typeof hex).toBe("function");
    });
});
