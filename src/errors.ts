/**
 * Typed errors for @browsercore/quic.
 *
 * Errors are part of the API — every failure mode is an explicit type so callers
 * can match on `kind` instead of parsing messages.
 */

/** Base class for all QUIC errors. */
export class QuicError extends Error {
    public readonly kind = "QuicError" as const;
    public override readonly cause: Error | undefined;

    constructor(message: string, options?: { cause?: Error }) {
        super(message, options);
        this.name = new.target.name;
        this.cause = options?.cause;
    }
}

/** The peer closed the connection with a CONNECTION_CLOSE frame. */
export class ConnectionClosedError extends Error {
    public readonly kind = "ConnectionClosedError" as const;
    /** Application error code (application-layer close) or transport error code. */
    public readonly errorCode: bigint;
    /** Frame type that triggered the close, if any. */
    public readonly frameType: bigint | undefined;
    /** Human-readable reason phrase. */
    public readonly reason: string;
    public override readonly cause: Error | undefined;

    constructor(
        errorCode: bigint,
        reason: string,
        options?: { frameType?: bigint; cause?: Error },
    ) {
        super(`CONNECTION_CLOSE: errorCode=${errorCode}, reason="${reason}"`);
        this.name = "ConnectionClosedError";
        this.errorCode = errorCode;
        this.frameType = options?.frameType;
        this.reason = reason;
        this.cause = options?.cause;
    }
}

/** The peer closed a specific stream with a STOP_SENDING frame. */
export class StopSendingError extends Error {
    public readonly kind = "StopSendingError" as const;
    public readonly streamId: bigint;
    public readonly errorCode: bigint;
    public override readonly cause: Error | undefined;

    constructor(streamId: bigint, errorCode: bigint, options?: { cause?: Error }) {
        super(`STOP_SENDING on stream ${streamId}: errorCode=${errorCode}`);
        this.name = "StopSendingError";
        this.streamId = streamId;
        this.errorCode = errorCode;
        this.cause = options?.cause;
    }
}

/** The peer reset a specific stream with a RESET_STREAM frame. */
export class ResetStreamError extends Error {
    public readonly kind = "ResetStreamError" as const;
    public readonly streamId: bigint;
    public readonly errorCode: bigint;
    public readonly finalSize: bigint;
    public override readonly cause: Error | undefined;

    constructor(streamId: bigint, errorCode: bigint, finalSize: bigint, options?: { cause?: Error }) {
        super(`RESET_STREAM on stream ${streamId}: errorCode=${errorCode}, finalSize=${finalSize}`);
        this.name = "ResetStreamError";
        this.streamId = streamId;
        this.errorCode = errorCode;
        this.finalSize = finalSize;
        this.cause = options?.cause;
    }
}

/** A flow-control window was violated (send exceeded the peer's limit). */
export class FlowControlError extends Error {
    public readonly kind = "FlowControlError" as const;
    public readonly streamId: bigint | undefined;
    public readonly limit: bigint;
    public readonly attempted: bigint;
    public override readonly cause: Error | undefined;

    constructor(limit: bigint, attempted: bigint, streamId?: bigint, options?: { cause?: Error }) {
        super(
            `Flow control violation: attempted ${attempted} bytes against limit ${limit} (stream ${streamId ?? "connection"})`,
        );
        this.name = "FlowControlError";
        this.streamId = streamId;
        this.limit = limit;
        this.attempted = attempted;
        this.cause = options?.cause;
    }
}

/** A packet could not be parsed from the wire. */
export class PacketParseError extends Error {
    public readonly kind = "PacketParseError" as const;
    public readonly offset: number;
    public override readonly cause: Error | undefined;

    constructor(offset: number, options?: { cause?: Error }) {
        super(`Packet parse error at offset ${offset}`);
        this.name = "PacketParseError";
        this.offset = offset;
        this.cause = options?.cause;
    }
}

/** A QUIC frame could not be parsed. */
export class FrameParseError extends Error {
    public readonly kind = "FrameParseError" as const;
    public readonly offset: number;
    public override readonly cause: Error | undefined;

    constructor(offset: number, options?: { cause?: Error }) {
        super(`Frame parse error at offset ${offset}`);
        this.name = "FrameParseError";
        this.offset = offset;
        this.cause = options?.cause;
    }
}

/** The peer violated the transport parameters we advertised. */
export class TransportParameterError extends Error {
    public readonly kind = "TransportParameterError" as const;
    public readonly parameter: number;
    public override readonly cause: Error | undefined;

    constructor(parameter: number, options?: { cause?: Error }) {
        super(`Transport parameter error: parameter=0x${parameter.toString(16)}`);
        this.name = "TransportParameterError";
        this.parameter = parameter;
        this.cause = options?.cause;
    }
}

/** A connection could not be established within the configured timeout. */
export class HandshakeTimeoutError extends Error {
    public readonly kind = "HandshakeTimeoutError" as const;
    public readonly timeoutMs: number;
    public override readonly cause: Error | undefined;

    constructor(timeoutMs: number, options?: { cause?: Error }) {
        super(`QUIC handshake not completed within ${timeoutMs}ms`);
        this.name = "HandshakeTimeoutError";
        this.timeoutMs = timeoutMs;
        this.cause = options?.cause;
    }
}
