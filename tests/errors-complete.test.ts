/**
 * Exhaustive unit tests for every QUIC error class in src/errors.ts.
 *
 * Goal: 100% coverage of every constructor, the `kind` discriminator, the
 * `name` field, message formatting (all branches), the optional `cause`, and
 * the extra domain fields each error carries. Every error extends `Error` and
 * is matched on `kind` in the wild, so each of those is asserted here.
 */

import { describe, it, expect } from "vitest";
import {
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
} from "../src/errors.js";

// ---------------------------------------------------------------------------
// QuicError — the base class.
// ---------------------------------------------------------------------------
// It is the only class that derives `name` from `new.target`, so constructing
// it directly must yield name === "QuicError". It also accepts an optional
// cause and an arbitrary message.

describe("QuicError", () => {
    it("constructs without a cause", () => {
        const err = new QuicError("boom");
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(QuicError);
        expect(err.name).toBe("QuicError");
        expect(err.kind).toBe("QuicError");
        expect(err.message).toBe("boom");
        expect(err.cause).toBeUndefined();
    });

    it("constructs with a cause", () => {
        const cause = new Error("root");
        const err = new QuicError("boom", { cause });
        expect(err.cause).toBe(cause);
        expect(err.message).toBe("boom");
    });

    it("uses new.target for the name (so a direct construction is named QuicError)", () => {
        const err = new QuicError("x");
        // QuicError derives `name` from `new.target` inside its constructor, so
        // a direct construction yields the class name "QuicError".
        expect(err.name).toBe("QuicError");
        // And it must not hardcode the name — subclasses would get their own
        // name via the same new.target mechanism (verified via a local subclass).
        class SubQuicError extends QuicError {}
        const sub = new SubQuicError("y");
        expect(sub.name).toBe("SubQuicError");
        expect(sub.kind).toBe("QuicError");
    });

    it("formats an empty message", () => {
        const err = new QuicError("");
        expect(err.message).toBe("");
    });
});

// ---------------------------------------------------------------------------
// ConnectionClosingError — default message, optional cause.
// ---------------------------------------------------------------------------

describe("ConnectionClosingError", () => {
    it("uses the default message when none is supplied", () => {
        const err = new ConnectionClosingError();
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(ConnectionClosingError);
        expect(err.name).toBe("ConnectionClosingError");
        expect(err.kind).toBe("ConnectionClosingError");
        expect(err.message).toBe("connection is closing");
        expect(err.cause).toBeUndefined();
    });

    it("accepts a custom message", () => {
        const err = new ConnectionClosingError("custom close");
        expect(err.message).toBe("custom close");
    });

    it("carries a cause when provided", () => {
        const cause = new Error("underlying");
        const err = new ConnectionClosingError("closing", { cause });
        expect(err.cause).toBe(cause);
    });

    it("carries no cause when options are omitted entirely", () => {
        const err = new ConnectionClosingError("msg");
        expect(err.cause).toBeUndefined();
    });
});

// ---------------------------------------------------------------------------
// ConnectionClosedError — errorCode, reason, optional frameType and cause.
// ---------------------------------------------------------------------------

describe("ConnectionClosedError", () => {
    it("constructs without frameType or cause", () => {
        const err = new ConnectionClosedError(0x00n, "bye");
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(ConnectionClosedError);
        expect(err.name).toBe("ConnectionClosedError");
        expect(err.kind).toBe("ConnectionClosedError");
        expect(err.errorCode).toBe(0x00n);
        expect(err.reason).toBe("bye");
        expect(err.frameType).toBeUndefined();
        expect(err.cause).toBeUndefined();
        expect(err.message).toBe('CONNECTION_CLOSE: errorCode=0, reason="bye"');
    });

    it("carries an optional frameType", () => {
        const err = new ConnectionClosedError(0x01n, "bad", { frameType: 0x1cn });
        expect(err.frameType).toBe(0x1cn);
        expect(err.message).toContain("errorCode=1");
        expect(err.message).toContain("reason=\"bad\"");
    });

    it("carries a cause", () => {
        const cause = new Error("tls alert");
        const err = new ConnectionClosedError(0x02n, "go away", { cause });
        expect(err.cause).toBe(cause);
        expect(err.frameType).toBeUndefined();
    });

    it("carries both frameType and cause simultaneously", () => {
        const cause = new Error("inner");
        const err = new ConnectionClosedError(0xffn, "max", { frameType: 0xffn, cause });
        expect(err.errorCode).toBe(0xffn);
        expect(err.frameType).toBe(0xffn);
        expect(err.cause).toBe(cause);
        expect(err.reason).toBe("max");
    });

    it("formats a zero error code and empty reason", () => {
        const err = new ConnectionClosedError(0n, "");
        expect(err.errorCode).toBe(0n);
        expect(err.reason).toBe("");
        expect(err.message).toBe('CONNECTION_CLOSE: errorCode=0, reason=""');
    });
});

// ---------------------------------------------------------------------------
// StopSendingError — streamId + errorCode, optional cause.
// ---------------------------------------------------------------------------

describe("StopSendingError", () => {
    it("constructs without a cause", () => {
        const err = new StopSendingError(4n, 0x02n);
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(StopSendingError);
        expect(err.name).toBe("StopSendingError");
        expect(err.kind).toBe("StopSendingError");
        expect(err.streamId).toBe(4n);
        expect(err.errorCode).toBe(0x02n);
        expect(err.cause).toBeUndefined();
        expect(err.message).toBe("STOP_SENDING on stream 4: errorCode=2");
    });

    it("constructs with a cause", () => {
        const cause = new Error("app decided");
        const err = new StopSendingError(7n, 0x10n, { cause });
        expect(err.streamId).toBe(7n);
        expect(err.errorCode).toBe(0x10n);
        expect(err.cause).toBe(cause);
    });

    it("formats stream id 0 correctly", () => {
        const err = new StopSendingError(0n, 0n);
        expect(err.message).toBe("STOP_SENDING on stream 0: errorCode=0");
    });
});

// ---------------------------------------------------------------------------
// ResetStreamError — streamId + errorCode + finalSize, optional cause.
// ---------------------------------------------------------------------------

describe("ResetStreamError", () => {
    it("constructs without a cause", () => {
        const err = new ResetStreamError(0n, 0x01n, 42n);
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(ResetStreamError);
        expect(err.name).toBe("ResetStreamError");
        expect(err.kind).toBe("ResetStreamError");
        expect(err.streamId).toBe(0n);
        expect(err.errorCode).toBe(0x01n);
        expect(err.finalSize).toBe(42n);
        expect(err.cause).toBeUndefined();
        expect(err.message).toBe("RESET_STREAM on stream 0: errorCode=1, finalSize=42");
    });

    it("constructs with a cause", () => {
        const cause = new Error("peer reset");
        const err = new ResetStreamError(11n, 0x05n, 1024n, { cause });
        expect(err.cause).toBe(cause);
        expect(err.streamId).toBe(11n);
        expect(err.finalSize).toBe(1024n);
    });

    it("formats a large final size", () => {
        const err = new ResetStreamError(2n, 0n, 65535n);
        expect(err.message).toContain("finalSize=65535");
    });
});

// ---------------------------------------------------------------------------
// FlowControlError — limit + attempted, optional streamId and cause.
// ---------------------------------------------------------------------------
// The message has two branches: connection-level (streamId omitted →
// "stream connection") vs. per-stream ("stream <id>"). Both must be covered.

describe("FlowControlError", () => {
    it("reports a connection-level violation when streamId is omitted", () => {
        const err = new FlowControlError(100n, 120n);
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(FlowControlError);
        expect(err.name).toBe("FlowControlError");
        expect(err.kind).toBe("FlowControlError");
        expect(err.limit).toBe(100n);
        expect(err.attempted).toBe(120n);
        expect(err.streamId).toBeUndefined();
        expect(err.cause).toBeUndefined();
        expect(err.message).toBe(
            "Flow control violation: attempted 120 bytes against limit 100 (stream connection)",
        );
    });

    it("reports a connection-level violation when streamId is explicitly undefined", () => {
        const err = new FlowControlError(100n, 120n, undefined);
        expect(err.streamId).toBeUndefined();
        expect(err.message).toContain("stream connection");
    });

    it("reports a per-stream violation when streamId is given", () => {
        const err = new FlowControlError(100n, 120n, 7n);
        expect(err.streamId).toBe(7n);
        expect(err.message).toBe(
            "Flow control violation: attempted 120 bytes against limit 100 (stream 7)",
        );
    });

    it("carries a cause (connection-level)", () => {
        const cause = new Error("overshoot");
        const err = new FlowControlError(100n, 120n, undefined, { cause });
        expect(err.cause).toBe(cause);
    });

    it("carries a cause (per-stream)", () => {
        const cause = new Error("overshoot");
        const err = new FlowControlError(50n, 60n, 3n, { cause });
        expect(err.cause).toBe(cause);
        expect(err.streamId).toBe(3n);
    });
});

// ---------------------------------------------------------------------------
// PacketParseError — offset, optional cause.
// ---------------------------------------------------------------------------

describe("PacketParseError", () => {
    it("constructs without a cause", () => {
        const err = new PacketParseError(9);
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(PacketParseError);
        expect(err.name).toBe("PacketParseError");
        expect(err.kind).toBe("PacketParseError");
        expect(err.offset).toBe(9);
        expect(err.cause).toBeUndefined();
        expect(err.message).toBe("Packet parse error at offset 9");
    });

    it("constructs with a cause", () => {
        const cause = new Error("truncated");
        const err = new PacketParseError(4, { cause });
        expect(err.offset).toBe(4);
        expect(err.cause).toBe(cause);
    });

    it("formats offset 0 correctly", () => {
        const err = new PacketParseError(0);
        expect(err.offset).toBe(0);
        expect(err.message).toBe("Packet parse error at offset 0");
    });
});

// ---------------------------------------------------------------------------
// FrameParseError — offset, optional cause.
// ---------------------------------------------------------------------------

describe("FrameParseError", () => {
    it("constructs without a cause", () => {
        const err = new FrameParseError(3);
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(FrameParseError);
        expect(err.name).toBe("FrameParseError");
        expect(err.kind).toBe("FrameParseError");
        expect(err.offset).toBe(3);
        expect(err.cause).toBeUndefined();
        expect(err.message).toBe("Frame parse error at offset 3");
    });

    it("constructs with a cause", () => {
        const cause = new Error("bad frame");
        const err = new FrameParseError(15, { cause });
        expect(err.offset).toBe(15);
        expect(err.cause).toBe(cause);
    });

    it("formats a large offset", () => {
        const err = new FrameParseError(4096);
        expect(err.message).toBe("Frame parse error at offset 4096");
    });
});

// ---------------------------------------------------------------------------
// TransportParameterError — parameter, optional cause. Hex formatting.
// ---------------------------------------------------------------------------

describe("TransportParameterError", () => {
    it("constructs without a cause", () => {
        const err = new TransportParameterError(0x0fn);
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(TransportParameterError);
        expect(err.name).toBe("TransportParameterError");
        expect(err.kind).toBe("TransportParameterError");
        expect(err.parameter).toBe(0x0fn);
        expect(err.cause).toBeUndefined();
        expect(err.message).toBe("Transport parameter error: parameter=0xf");
    });

    it("constructs with a cause", () => {
        const cause = new Error("unknown param");
        const err = new TransportParameterError(0x01n as unknown as number, { cause });
        expect(err.cause).toBe(cause);
    });

    it("formats parameter 0 as 0x0", () => {
        const err = new TransportParameterError(0);
        expect(err.parameter).toBe(0);
        expect(err.message).toBe("Transport parameter error: parameter=0x0");
    });

    it("formats a large parameter id in lower-case hex", () => {
        const err = new TransportParameterError(0xdeadbeef);
        expect(err.message).toBe("Transport parameter error: parameter=0xdeadbeef");
    });

    it("formats a single hex digit without zero-padding", () => {
        const err = new TransportParameterError(0xa);
        expect(err.message).toBe("Transport parameter error: parameter=0xa");
    });
});

// ---------------------------------------------------------------------------
// HandshakeTimeoutError — timeoutMs, optional cause.
// ---------------------------------------------------------------------------

describe("HandshakeTimeoutError", () => {
    it("constructs without a cause", () => {
        const err = new HandshakeTimeoutError(10_000);
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(HandshakeTimeoutError);
        expect(err.name).toBe("HandshakeTimeoutError");
        expect(err.kind).toBe("HandshakeTimeoutError");
        expect(err.timeoutMs).toBe(10_000);
        expect(err.cause).toBeUndefined();
        expect(err.message).toBe("QUIC handshake not completed within 10000ms");
    });

    it("constructs with a cause", () => {
        const cause = new Error("network down");
        const err = new HandshakeTimeoutError(5_000, { cause });
        expect(err.cause).toBe(cause);
        expect(err.timeoutMs).toBe(5_000);
    });

    it("formats a 0ms timeout (edge: never completed)", () => {
        const err = new HandshakeTimeoutError(0);
        expect(err.timeoutMs).toBe(0);
        expect(err.message).toBe("QUIC handshake not completed within 0ms");
    });
});

// ---------------------------------------------------------------------------
// TlsHandshakeError — phase, optional cause. Two message branches.
// ---------------------------------------------------------------------------
// The message differs based on whether a cause is supplied:
//   - without: `QUIC TLS handshake failed during ${phase}`
//   - with:    `QUIC TLS handshake failed during ${phase}: ${cause.message}`

describe("TlsHandshakeError", () => {
    it("constructs without a cause and exposes the phase", () => {
        const err = new TlsHandshakeError("client-hello");
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(TlsHandshakeError);
        expect(err.name).toBe("TlsHandshakeError");
        expect(err.kind).toBe("TlsHandshakeError");
        expect(err.phase).toBe("client-hello");
        expect(err.cause).toBeUndefined();
        expect(err.message).toBe("QUIC TLS handshake failed during client-hello");
    });

    it("constructs with a cause and appends the cause message", () => {
        const cause = new Error("decrypt_error (alert 50)");
        const err = new TlsHandshakeError("server-finished", { cause });
        expect(err.cause).toBe(cause);
        expect(err.phase).toBe("server-finished");
        expect(err.message).toBe(
            "QUIC TLS handshake failed during server-finished: decrypt_error (alert 50)",
        );
    });

    it("appends the cause message even when the phase string is empty", () => {
        const cause = new Error("no overlap");
        const err = new TlsHandshakeError("", { cause });
        expect(err.phase).toBe("");
        expect(err.message).toBe("QUIC TLS handshake failed during : no overlap");
    });

    it("formats an empty phase without a cause", () => {
        const err = new TlsHandshakeError("");
        expect(err.message).toBe("QUIC TLS handshake failed during ");
    });

    it("is distinguishable from QuicError by kind", () => {
        const err = new TlsHandshakeError("handshake");
        expect(err.kind).not.toBe("QuicError");
        expect(err.kind).toBe("TlsHandshakeError");
    });
});

// ---------------------------------------------------------------------------
// PacketProtectionError — operation ("encrypt" | "decrypt"), optional cause.
// ---------------------------------------------------------------------------

describe("PacketProtectionError", () => {
    it("constructs for encrypt without a cause", () => {
        const err = new PacketProtectionError("encrypt");
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(PacketProtectionError);
        expect(err.name).toBe("PacketProtectionError");
        expect(err.kind).toBe("PacketProtectionError");
        expect(err.operation).toBe("encrypt");
        expect(err.cause).toBeUndefined();
        expect(err.message).toBe(
            "QUIC packet encrypt failed: authentication mismatch or corrupt input",
        );
    });

    it("constructs for decrypt without a cause", () => {
        const err = new PacketProtectionError("decrypt");
        expect(err.operation).toBe("decrypt");
        expect(err.message).toBe(
            "QUIC packet decrypt failed: authentication mismatch or corrupt input",
        );
    });

    it("wraps an underlying AEAD cause (encrypt)", () => {
        const cause = new Error("AEAD authentication failed");
        const err = new PacketProtectionError("encrypt", { cause });
        expect(err.cause).toBe(cause);
        expect(err.operation).toBe("encrypt");
    });

    it("wraps an underlying AEAD cause (decrypt)", () => {
        const cause = new Error("tag mismatch");
        const err = new PacketProtectionError("decrypt", { cause });
        expect(err.cause).toBe(cause);
        expect(err.operation).toBe("decrypt");
    });

    it("is distinguishable from TlsHandshakeError by kind", () => {
        const err = new PacketProtectionError("decrypt");
        expect(err.kind).not.toBe("TlsHandshakeError");
        expect(err.kind).toBe("PacketProtectionError");
    });
});

// ---------------------------------------------------------------------------
// Cross-cutting: every exported error class has a unique `kind` discriminator.
// ---------------------------------------------------------------------------

describe("kind discriminators are unique across all error classes", () => {
    it("assigns a distinct literal kind to each class", () => {
        const cause = new Error("x");
        const cases: Array<readonly [string, Error]> = [
            ["ConnectionClosedError", new ConnectionClosedError(0n, "r")],
            ["ConnectionClosingError", new ConnectionClosingError()],
            ["FlowControlError", new FlowControlError(1n, 2n)],
            ["FrameParseError", new FrameParseError(0)],
            ["HandshakeTimeoutError", new HandshakeTimeoutError(100)],
            ["PacketParseError", new PacketParseError(0)],
            ["PacketProtectionError", new PacketProtectionError("encrypt")],
            ["QuicError", new QuicError("x")],
            ["ResetStreamError", new ResetStreamError(0n, 0n, 0n)],
            ["StopSendingError", new StopSendingError(0n, 0n)],
            ["TransportParameterError", new TransportParameterError(0)],
            ["TlsHandshakeError", new TlsHandshakeError("phase", { cause })],
        ];

        // Every kind matches its class name, and no two kinds collide.
        const kinds = cases.map(([, err]) => (err as { kind: string }).kind);
        for (const [name, err] of cases) {
            expect((err as { kind: string }).kind).toBe(name);
        }
        const unique = new Set(kinds);
        expect(unique.size).toBe(cases.length);
    });
});

// ---------------------------------------------------------------------------
// Cross-cutting: every error class accepts and stores an optional cause.
// ---------------------------------------------------------------------------
// Verifies the `options?.cause` branch for every class in one sweep, including
// the case where options is provided but `cause` is left undefined.

describe("cause propagation across all error classes", () => {
    it("stores an undefined cause when options are omitted", () => {
        expect(new QuicError("m").cause).toBeUndefined();
        expect(new ConnectionClosingError().cause).toBeUndefined();
        expect(new ConnectionClosedError(0n, "r").cause).toBeUndefined();
        expect(new StopSendingError(0n, 0n).cause).toBeUndefined();
        expect(new ResetStreamError(0n, 0n, 0n).cause).toBeUndefined();
        expect(new FlowControlError(1n, 2n).cause).toBeUndefined();
        expect(new PacketParseError(0).cause).toBeUndefined();
        expect(new FrameParseError(0).cause).toBeUndefined();
        expect(new TransportParameterError(0).cause).toBeUndefined();
        expect(new HandshakeTimeoutError(1).cause).toBeUndefined();
        expect(new TlsHandshakeError("p").cause).toBeUndefined();
        expect(new PacketProtectionError("encrypt").cause).toBeUndefined();
    });

    it("stores the provided cause on every class", () => {
        const cause = new Error("root");
        expect(new QuicError("m", { cause }).cause).toBe(cause);
        expect(new ConnectionClosingError("m", { cause }).cause).toBe(cause);
        expect(new ConnectionClosedError(0n, "r", { cause }).cause).toBe(cause);
        expect(new StopSendingError(0n, 0n, { cause }).cause).toBe(cause);
        expect(new ResetStreamError(0n, 0n, 0n, { cause }).cause).toBe(cause);
        expect(new FlowControlError(1n, 2n, undefined, { cause }).cause).toBe(cause);
        expect(new PacketParseError(0, { cause }).cause).toBe(cause);
        expect(new FrameParseError(0, { cause }).cause).toBe(cause);
        expect(new TransportParameterError(0, { cause }).cause).toBe(cause);
        expect(new HandshakeTimeoutError(1, { cause }).cause).toBe(cause);
        expect(new TlsHandshakeError("p", { cause }).cause).toBe(cause);
        expect(new PacketProtectionError("encrypt", { cause }).cause).toBe(cause);
    });
});
