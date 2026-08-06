/**
 * @browsercore/quic — public API surface.
 *
 * QUIC transport (RFC 9000) over a datagram (UDP) transport. No knowledge of
 * HTTP/3, TLS handshake semantics, or sockets — it composes exclusively over an
 * injected {@link DatagramTransport} and an injected `CryptoProvider`. Higher
 * layers (http3) compose through {@link QuicConnection}.
 */

export { connectQuic, QuicConnectionImpl } from "./connection.js";

export {
    ConnectionClosedError,
    ConnectionClosingError,
    FlowControlError,
    FrameParseError,
    HandshakeTimeoutError,
    PacketParseError,
    PacketProtectionError,
    QuicError,
    ResetStreamError,
    StopSendingError,
    TransportParameterError,
    TlsHandshakeError,
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
    makeConnectionId,
    makeStreamId,
    nextStreamId,
    streamIdIsBidirectional,
    streamIdIsClientInitiated,
    systemClock,
} from "./types.js";

export { VARINT_MAX } from "./frame/varint.js";

export {
    type BaseQuicFrame,
    type Clock,
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
    type ClientHelloConfigLike,
    type ProtocolVersionLike,
} from "./types.js";

// Re-export Logger from ts-log for consistency across all browsercore packages
export { type Logger, dummyLogger } from "ts-log";
/** @deprecated Use {@link dummyLogger} instead. */
export { dummyLogger as silentLogger } from "ts-log";
// Export devLogger for development use
export { devLogger } from "./types.js";

export {
    decodeVarint,
    encodeVarint,
    encodeVarintInto,
    getVarintEncodedLength,
    prefixMask,
} from "./frame/varint.js";
export { decodeFrame, readFrames, serializeFrame } from "./frame/frame.js";
export {
    parsePacketHeader,
    serializeShortHeader,
    serializeLongHeader,
    decodePacketNumber,
    encodePacketNumber,
} from "./packet/packet.js";
export type { PacketHeader, LongHeader, ShortHeader } from "./packet/packet.js";
export { createStreamManager } from "./stream/stream.js";
export type { StreamManager } from "./stream/stream.js";

export { assertNever, concat, concatAll, hex } from "./utils.js";

export {
    decodeTransportParameters,
    encodeTransportParameters,
    fromWireParameters,
    toWireParameters,
} from "./transport-params.js";
export type { TransportParameters } from "./transport-params.js";

// --- QUIC packet protection (RFC 9001 §5) ----------------------------------
export {
    constructNonce,
    encryptPayload,
    decryptPayload,
    computeHeaderProtectionMask,
    applyHeaderProtection,
    removeHeaderProtection,
    protectPayload,
    unprotectPayload,
    type QuicAead,
} from "./packet/packet-protection.js";

// --- QUIC key derivation (RFC 9001 §5) -------------------------------------
export {
    quicHkdfExpandLabel,
    deriveQuicSecrets,
    deriveInitialSecrets,
    INITIAL_SALT_V1,
    QUIC_IV_LENGTH,
    type QuicProtectionSecrets,
    type InitialSecrets,
} from "./crypto/key-derivation.js";

// --- QUIC TLS handshake (RFC 9001 §4, §8) ----------------------------------
export {
    runQuicHandshake,
    adaptQuicStreamToTransport,
    QuicTransportAdapter,
    type QuicKeyPhase,
    type QuicPhaseSecrets,
    type QuicHandshakeResult,
} from "./handshake/index.js";
