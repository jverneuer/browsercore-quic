/**
 * @browsercore/quic — public API surface.
 *
 * QUIC transport (RFC 9000) over a datagram (UDP) transport. No knowledge of
 * HTTP/3, TLS handshake semantics, or sockets — it composes exclusively over an
 * injected {@link DatagramTransport} and `@browsercore/crypto`. Higher layers
 * (http3) compose through {@link QuicConnection}.
 */

export { connectQuic, QuicConnectionImpl } from "./connection.js";

export {
    ConnectionClosedError,
    FlowControlError,
    FrameParseError,
    HandshakeTimeoutError,
    PacketParseError,
    QuicError,
    ResetStreamError,
    StopSendingError,
    TransportParameterError,
} from "./errors.js";

export {
    LongPacketType,
    QuicFrameType,
    TransportParameter,
    type LongPacketTypeValue,
    type QuicFrame,
    type QuicFrameTypeValue,
} from "./types.js";

export {
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
} from "./types.js";

export { VARINT_MAX } from "./frame/varint.js";

export {
    type BaseQuicFrame,
    type ConnectionId,
    type DatagramCloseReason,
    type DatagramTransport,
    type QuicConnection,
    type QuicOptions,
    type QuicStream,
    type QuicTransportParameters,
    type StreamId,
    type StreamState,
    type StreamCloseReason,
    type UdpAddress,
} from "./types.js";

export { decodeVarint, encodeVarint, getVarintEncodedLength } from "./frame/varint.js";
export { decodeFrame, readFrames, serializeFrame } from "./frame/frame.js";
export { createStreamManager } from "./stream/stream.js";
export type { StreamManager } from "./stream/stream.js";

export { assertNever, concat, concatAll, hex } from "./utils.js";
