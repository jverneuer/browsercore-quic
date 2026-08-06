import type {
    DatagramTransport,
    UdpAddress,
    DatagramCloseReason,
    RandomSource,
} from "@browsercore/transport";

/**
 * Domain types for @browsercore/quic.
 *
 * QUIC transport (RFC 9000) over a datagram (UDP) transport. This package owns
 * NO knowledge of HTTP/3, TLS handshake semantics, or sockets — it composes
 * exclusively over an injected {@link DatagramTransport} and an injected
 * CryptoProvider. Higher layers (http3) compose through
 * {@link QuicConnection}.
 *
 * Key concepts that shape these types:
 *   - QUIC is datagram-based (UDP), not a byte stream. Packets carry frames;
 *     frames carry stream data. Reliability and ordering are per-stream, not
 *     per-connection.
 *   - Long headers (Initial, Handshake, 0-RTT, Retry) are used during the
 *   - handshake; short headers (1-RTT) are used for data after the handshake.
 *   - Connection ids route packets and survive NAT rebinding.
 *   - Streams are bidirectional or unidirectional, each with independent flow
 *     control. The 62-bit stream id's low 2 bits encode initiator + direction.
 */

// ---------------------------------------------------------------------------
// Clock abstraction (injected — makes time-dependent logic testable)
// ---------------------------------------------------------------------------

/**
 * A source of the current time. Injected so connection id generation and any
 * future time-driven logic can be tested deterministically. {@link systemClock}
 * is the production default; tests supply a fake.
 */
export interface Clock {
    /** Current time in milliseconds since the Unix epoch (same unit as Date.now()). */
    now(): number;
}

/** Production clock backed by the global Date. */
export const systemClock: Clock = { now: () => Date.now() };

// Datagram transport types — imported from @browsercore/transport.
// (Re-exported here so consumers can pull them from the quic package too.)
export type { DatagramTransport, UdpAddress, DatagramCloseReason };

// ---------------------------------------------------------------------------
// Connection ids (RFC 9000 §5.1)
// ---------------------------------------------------------------------------

/** A QUIC connection id (0–255 bytes, typically 0/8/16). */
export type ConnectionId = Uint8Array & { __brand: "ConnectionId" };

/** Brand a byte array as a {@link ConnectionId}. Use at trust boundaries
 * (e.g. when constructing an id from the wire or from scratch). */
export function makeConnectionId(bytes: Uint8Array): ConnectionId {
    return bytes as ConnectionId;
}

/** The zero-length connection id constant. */
export const EMPTY_CONNECTION_ID = makeConnectionId(new Uint8Array(0));

// ---------------------------------------------------------------------------
// QUIC packet types (RFC 9000 §17)
// ---------------------------------------------------------------------------

/** Long header packet types, encoded in the low 2 bits of the first byte. */
export const LongPacketType = {
    INITIAL: 0b00,
    ZERO_RTT: 0b01,
    HANDSHAKE: 0b10,
    RETRY: 0b11,
} as const;

export type LongPacketTypeValue = (typeof LongPacketType)[keyof typeof LongPacketType];

/** The fixed first-bit flag: 1 = long header, 0 = short header (1-RTT). */
export const HEADER_FORM_LONG = 1;
export const HEADER_FORM_SHORT = 0;

/** The bit mask for the long packet type in the first byte. */
export const LONG_PACKET_TYPE_MASK = 0x03;

// ---------------------------------------------------------------------------
// QUIC frame types (RFC 9000 §12.4) — encoded as a varint
// ---------------------------------------------------------------------------

/** QUIC frame type identifiers. */
export const QuicFrameType = {
    PADDING: 0x00,
    PING: 0x01,
    ACK: 0x02, // 0x02 and 0x03 (with/without ECN)
    ACK_ECN: 0x03,
    RESET_STREAM: 0x04,
    STOP_SENDING: 0x05,
    CRYPTO: 0x06,
    NEW_TOKEN: 0x07,
    STREAM: 0x08, // 0x08..0x0f (off/len/fin bits)
    MAX_DATA: 0x10,
    MAX_STREAM_DATA: 0x11,
    MAX_STREAMS_BIDI: 0x12,
    MAX_STREAMS_UNI: 0x13,
    DATA_BLOCKED: 0x14,
    STREAM_DATA_BLOCKED: 0x15,
    STREAMS_BLOCKED_BIDI: 0x16,
    STREAMS_BLOCKED_UNI: 0x17,
    NEW_CONNECTION_ID: 0x18,
    RETIRE_CONNECTION_ID: 0x19,
    PATH_CHALLENGE: 0x1a,
    PATH_RESPONSE: 0x1b,
    CONNECTION_CLOSE: 0x1c, // transport error
    CONNECTION_CLOSE_APP: 0x1d, // application error
    HANDSHAKE_DONE: 0x1e,
} as const;

export type QuicFrameTypeValue = (typeof QuicFrameType)[keyof typeof QuicFrameType];

/** The bit mask for the STREAM frame's offset/length/fin bits. */
export const STREAM_OFF_BIT = 0x04;
export const STREAM_LEN_BIT = 0x02;
export const STREAM_FIN_BIT = 0x01;

// ---------------------------------------------------------------------------
// QUIC transport parameters (RFC 9000 §18.2) — encoded as varint id + varint length + value
// ---------------------------------------------------------------------------

/** Transport parameter identifiers. */
export const TransportParameter = {
    ORIGINAL_DESTINATION_CONNECTION_ID: 0x00,
    MAX_IDLE_TIMEOUT: 0x01,
    STATELESS_RESET_TOKEN: 0x02,
    MAX_UDP_PAYLOAD_SIZE: 0x03,
    INITIAL_MAX_DATA: 0x04,
    INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: 0x05,
    INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: 0x06,
    INITIAL_MAX_STREAM_DATA_UNI: 0x07,
    INITIAL_MAX_STREAMS_BIDI: 0x08,
    INITIAL_MAX_STREAMS_UNI: 0x09,
    ACK_DELAY_EXPONENT: 0x0a,
    MAX_ACK_DELAY: 0x0b,
    DISABLE_ACTIVE_MIGRATION: 0x0c,
    PREFERRED_ADDRESS: 0x0d,
    ACTIVE_CONNECTION_ID_LIMIT: 0x0e,
    INITIAL_SOURCE_CONNECTION_ID: 0x0f,
    RETIRE_CONNECTION_ID: 0x10, // actually RETIRE_PRIOR_TO = 0x10 is in TLS; see RFC
    RETRY_SOURCE_CONNECTION_ID: 0x10, // (0x10 is not assigned; kept for completeness)
    VERSION_NEGOTIATION: 0x11, // not a real param id; placeholder
} as const;

export type TransportParameterKey = (typeof TransportParameter)[keyof typeof TransportParameter];

/** The minimum max UDP payload size QUIC requires (RFC 9000 §14). */
export const MIN_MAX_UDP_PAYLOAD_SIZE = 1200;

// ---------------------------------------------------------------------------
// QUIC frames — discriminated union over `type`
// ---------------------------------------------------------------------------

/** The common QUIC frame shape — discriminated by `type`. */
export interface BaseQuicFrame {
    readonly type: QuicFrameTypeValue;
}

export interface PaddingFrame extends BaseQuicFrame {
    readonly type: typeof QuicFrameType.PADDING;
}

export interface PingFrame extends BaseQuicFrame {
    readonly type: typeof QuicFrameType.PING;
}

export interface AckRange {
    readonly gap: bigint;
    readonly ackRangeLength: bigint;
}

export interface AckFrame extends BaseQuicFrame {
    readonly type: typeof QuicFrameType.ACK | typeof QuicFrameType.ACK_ECN;
    readonly largestAck: bigint;
    readonly ackDelay: bigint;
    readonly ackRangeCount: bigint;
    readonly firstAckRange: bigint;
    readonly ackRanges: readonly AckRange[];
    readonly ecnCounts?: { readonly ect0: bigint; readonly ect1: bigint; readonly ce: bigint };
}

export interface ResetStreamFrame extends BaseQuicFrame {
    readonly type: typeof QuicFrameType.RESET_STREAM;
    readonly streamId: bigint;
    readonly errorCode: bigint;
    readonly finalSize: bigint;
}

export interface StopSendingFrame extends BaseQuicFrame {
    readonly type: typeof QuicFrameType.STOP_SENDING;
    readonly streamId: bigint;
    readonly errorCode: bigint;
}

export interface CryptoFrame extends BaseQuicFrame {
    readonly type: typeof QuicFrameType.CRYPTO;
    readonly offset: bigint;
    readonly data: Uint8Array;
}

export interface NewTokenFrame extends BaseQuicFrame {
    readonly type: typeof QuicFrameType.NEW_TOKEN;
    readonly token: Uint8Array;
}

export interface StreamFrame extends BaseQuicFrame {
    readonly type: typeof QuicFrameType.STREAM;
    readonly streamId: bigint;
    readonly offset: bigint;
    readonly data: Uint8Array;
    /** True if the FIN bit is set — this is the last byte on the stream. */
    readonly fin: boolean;
}

export interface MaxDataFrame extends BaseQuicFrame {
    readonly type: typeof QuicFrameType.MAX_DATA;
    readonly maximum: bigint;
}

export interface MaxStreamDataFrame extends BaseQuicFrame {
    readonly type: typeof QuicFrameType.MAX_STREAM_DATA;
    readonly streamId: bigint;
    readonly maximum: bigint;
}

export interface MaxStreamsFrame extends BaseQuicFrame {
    readonly type:
        | typeof QuicFrameType.MAX_STREAMS_BIDI
        | typeof QuicFrameType.MAX_STREAMS_UNI;
    readonly maximum: bigint;
}

export interface DataBlockedFrame extends BaseQuicFrame {
    readonly type: typeof QuicFrameType.DATA_BLOCKED;
    readonly limit: bigint;
}

export interface StreamDataBlockedFrame extends BaseQuicFrame {
    readonly type: typeof QuicFrameType.STREAM_DATA_BLOCKED;
    readonly streamId: bigint;
    readonly limit: bigint;
}

export interface StreamsBlockedFrame extends BaseQuicFrame {
    readonly type:
        | typeof QuicFrameType.STREAMS_BLOCKED_BIDI
        | typeof QuicFrameType.STREAMS_BLOCKED_UNI;
    readonly limit: bigint;
}

export interface NewConnectionIdFrame extends BaseQuicFrame {
    readonly type: typeof QuicFrameType.NEW_CONNECTION_ID;
    readonly sequenceNumber: bigint;
    readonly retirePriorTo: bigint;
    readonly connectionId: ConnectionId;
    readonly statelessResetToken: Uint8Array;
}

export interface RetireConnectionIdFrame extends BaseQuicFrame {
    readonly type: typeof QuicFrameType.RETIRE_CONNECTION_ID;
    readonly sequenceNumber: bigint;
}

export interface PathChallengeFrame extends BaseQuicFrame {
    readonly type: typeof QuicFrameType.PATH_CHALLENGE;
    readonly data: Uint8Array; // 8 bytes
}

export interface PathResponseFrame extends BaseQuicFrame {
    readonly type: typeof QuicFrameType.PATH_RESPONSE;
    readonly data: Uint8Array; // 8 bytes
}

export interface ConnectionCloseFrame extends BaseQuicFrame {
    readonly type:
        | typeof QuicFrameType.CONNECTION_CLOSE
        | typeof QuicFrameType.CONNECTION_CLOSE_APP;
    readonly errorCode: bigint;
    readonly frameType: bigint | undefined;
    readonly reason: string;
}

export interface HandshakeDoneFrame extends BaseQuicFrame {
    readonly type: typeof QuicFrameType.HANDSHAKE_DONE;
}

/** Every QUIC frame variant — exhaustive discriminated union. */
export type QuicFrame =
    | PaddingFrame
    | PingFrame
    | AckFrame
    | ResetStreamFrame
    | StopSendingFrame
    | CryptoFrame
    | NewTokenFrame
    | StreamFrame
    | MaxDataFrame
    | MaxStreamDataFrame
    | MaxStreamsFrame
    | DataBlockedFrame
    | StreamDataBlockedFrame
    | StreamsBlockedFrame
    | NewConnectionIdFrame
    | RetireConnectionIdFrame
    | PathChallengeFrame
    | PathResponseFrame
    | ConnectionCloseFrame
    | HandshakeDoneFrame;

// ---------------------------------------------------------------------------
// Stream model (RFC 9000 §2)
// ---------------------------------------------------------------------------

/** Stream id is a 62-bit unsigned integer; low 2 bits encode type. */
export type StreamId = bigint & { __brand: "StreamId" };

/** Create a StreamId from a raw value, validating the 62-bit range. */
export function makeStreamId(value: bigint): StreamId {
    if (value < 0n || value > (1n << 62n) - 1n) {
        throw new RangeError(`stream id out of range: ${value}`);
    }
    return value as StreamId;
}

/** The two least-significant bits of a stream id encode initiator + direction. */
export function streamIdIsClientInitiated(id: StreamId): boolean {
    return (id & 1n) === 0n;
}

export function streamIdIsBidirectional(id: StreamId): boolean {
    return (id & 2n) === 0n;
}

/**
 * Compute the first stream id for a given type (RFC 9000 §2.1). Client-
 * initiated bidirectional streams start at 0; each subsequent stream of the
 * same type increments by 4.
 */
export function firstStreamId(bidirectional: boolean, clientInitiated: boolean): StreamId {
    // Low 2 bits encode direction (bit 1) and initiator (bit 0).
    // Bidirectional=0b10 bit clear, unidirectional=set; client=bit clear, server=set.
    const typeBits = (bidirectional ? 0n : 2n) | (clientInitiated ? 0n : 1n);
    return makeStreamId(typeBits);
}

/** Compute the next valid stream id of the same type (increment by 4). */
export function nextStreamId(current: StreamId): StreamId {
    return makeStreamId(current + 4n);
}

/** Lifecycle state of a QUIC stream. */
export type StreamState =
    | { readonly state: "open" }
    | { readonly state: "half_closed_local" }
    | { readonly state: "half_closed_remote" }
    | { readonly state: "closed"; readonly reason: StreamCloseReason };

/** Why a stream entered the `closed` state. */
export type StreamCloseReason =
    | { readonly kind: "reset"; readonly errorCode: bigint }
    | { readonly kind: "stop_sending"; readonly errorCode: bigint }
    | { readonly kind: "normal" }
    | { readonly kind: "connection_close" };

// ---------------------------------------------------------------------------
// QUIC stream + connection interfaces (the contract HTTP/3 consumes)
// ---------------------------------------------------------------------------

/** A bidirectional or unidirectional QUIC stream: a reliable, ordered byte stream. */
export interface QuicStream {
    /** QUIC stream id (62-bit). */
    readonly id: StreamId;
    /** Write bytes to the stream. Resolves when handed to the QUIC layer / buffered. */
    write(data: Uint8Array): Promise<void>;
    /** Read the next chunk of bytes, or reject if the stream closes first. */
    read(): Promise<Uint8Array>;
    /** Close the stream (send FIN / RESET_STREAM). */
    close(): Promise<void>;
}

/**
 * Public contract for a QUIC connection. This is the interface HTTP/3 depends
 * on — implemented by this package's `QuicConnectionImpl`, consumed by
 * `@browsercore/http3`.
 */
export interface QuicConnection {
    /** Opaque identifier for logging / correlation. */
    readonly id: string;
    /** Open a new bidirectional stream (request/response). */
    openBidirectionalStream(): Promise<QuicStream>;
    /** Accept the next incoming bidirectional stream from the peer. */
    acceptBidirectionalStream(): Promise<QuicStream>;
    /** Open a new unidirectional stream (control / QPACK / push). */
    openUnidirectionalStream(): Promise<QuicStream>;
    /** Accept the next incoming unidirectional stream from the peer. */
    acceptUnidirectionalStream(): Promise<QuicStream>;
    /** Close the QUIC connection with an error code and reason. */
    close(errorCode: bigint, reason: string): Promise<void>;
    /**
     * Send a PATH_CHALLENGE to validate a path (RFC 9000 §8.2.1, §19.17).
     * Records the 8-byte challenge so a matching PATH_RESPONSE from the peer
     * validates the path.
     */
    sendPathChallenge(data: Uint8Array): void;
    /** True if a PATH_CHALLENGE with the given data is awaiting a PATH_RESPONSE. */
    hasPendingPathChallenge(data: Uint8Array): boolean;
}

// ---------------------------------------------------------------------------
// Logger abstraction (injected — this package never touches `console`)
// ---------------------------------------------------------------------------

/**
 * The logging sink QUIC consumes. Injected so the package never writes to
 * `console` directly — callers supply a real logger in dev/production and a
 * no-op ({@link silentLogger}) by default so tests and embedded consumers
 * stay silent unless they opt in via {@link QuicOptions.logger}.
 *
 * Method names track the calls they replace: `debug` replaces the log-level
 * sink, `warn` replaces the warn-level sink, `error` replaces the error-level
 * sink — so callers migrate by mapping each severity to its Logger method.
 */
export interface Logger {
    /** Informational / trace output (log-level sink). */
    readonly debug: (...args: unknown[]) => void;
    /** Recoverable anomaly (warn-level sink). */
    readonly warn: (...args: unknown[]) => void;
    /** Hard failure (error-level sink). */
    readonly error: (...args: unknown[]) => void;
}

/** No-op logger — the default. Every call is a silent drop. */
export const silentLogger: Logger = {
    debug: () => {},
    warn: () => {},
    error: () => {},
};

/** Development logger that delegates to the global console. */
const sysConsole = console;
export const devLogger: Logger = {
    debug: (...args) => {
        sysConsole.debug(...args);
    },
    warn: (...args) => {
        sysConsole.warn(...args);
    },
    error: (...args) => {
        sysConsole.error(...args);
    },
};

// ---------------------------------------------------------------------------
// QuicOptions
// ---------------------------------------------------------------------------

/** Options for {@link connectQuic}. */
export interface QuicOptions {
    /** The underlying datagram (UDP) transport (already bound). */
    readonly transport: DatagramTransport;
    /** The peer's UDP address. */
    readonly peer: UdpAddress;
    /** Server name (SNI) for the handshake. */
    readonly serverName: string;
    /** Connection id to use for the handshake. */
    readonly initialDcid: ConnectionId;
    /** Our initial source connection id. */
    readonly initialScid: ConnectionId;
    /** Handshake timeout in milliseconds. Default 10_000. */
    readonly handshakeTimeoutMs?: number;
    /** Our transport parameters to advertise. */
    readonly transportParameters?: QuicTransportParameters;
    /**
     * Clock source for time-driven logic. Defaults to {@link systemClock}.
     * Inject a fake in tests to make connection id generation deterministic.
     */
    readonly clock?: Clock;
    /**
     * Random source for connection-id generation and packet-number placeholders.
     * Defaults to {@link nodeRandomSource}. Inject a deterministic source in
     * tests to make wire bytes reproducible.
     */
    readonly random?: RandomSource;
    /**
     * Logging sink. Defaults to {@link silentLogger} so tests and embedded
     * consumers stay silent unless they opt in.
     */
    readonly logger?: Logger;
    /**
     * Skip the TLS handshake and return an unprotected connection. The data
     * plane is fully functional and testable with a fake datagram transport,
     * but the connection is not wire-ready without a protection + handshake
     * layer on top.
     */
    readonly skipHandshake?: boolean;
    /**
     * TLS ClientHello configuration for the handshake. Defaults to a modern
     * TLS 1.3 profile (X25519 + secp256r1 key shares, AES-256/128-GCM +
     * ChaCha20-Poly1305).
     */
    readonly tlsProfile?: ClientHelloConfigLike;
}

/** QUIC transport parameters the local endpoint advertises. */
export interface QuicTransportParameters {
    readonly maxIdleTimeoutMs?: number;
    readonly maxUdpPayloadSize?: number;
    readonly initialMaxData?: bigint;
    readonly initialMaxStreamDataBidiLocal?: bigint;
    readonly initialMaxStreamDataBidiRemote?: bigint;
    readonly initialMaxStreamDataUni?: bigint;
    readonly initialMaxStreamsBidi?: bigint;
    readonly initialMaxStreamsUni?: bigint;
    readonly activeConnectionIdLimit?: number;
}

/**
 * A subset of @browsercore/tls's `ClientHelloConfig` that QUIC needs to drive
 * the handshake. We define a local interface (rather than importing the full
 * TLS type) so that the QUIC package's public options surface stays decoupled
 * from TLS internals — callers can pass a plain object literal.
 */
export interface ClientHelloConfigLike {
    /** Ordered list of cipher suites the client advertises (most-preferred first). */
    readonly cipherSuites: readonly string[];
    /** Extension types in the exact order they must appear in the ClientHello. */
    readonly extensionOrder: readonly number[];
    /** Named groups for key share, ordered by preference. */
    readonly keyShareGroups: readonly string[];
    /** Signature algorithms the client accepts in CertificateVerify. */
    readonly signatureAlgorithms: readonly string[];
    /** Protocol versions the client advertises via supported_versions. */
    readonly supportedVersions: readonly ProtocolVersionLike[];
    /** Server Name Indication hostname (SNI). */
    readonly serverName: string;
    /** ALPN protocols the client wishes to negotiate. */
    readonly alpnProtocols?: readonly string[];
    /** Whether to inject GREASE (RFC 8701) sentinel values. */
    readonly grease: boolean;
}

/** A protocol version as advertised via supported_versions. */
export interface ProtocolVersionLike {
    readonly name: "TLS 1.2" | "TLS 1.3";
    readonly wire: number;
}
