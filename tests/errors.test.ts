/**
 * Error-type unit tests for @browsercore/quic.
 *
 * Every error class is part of the public API (exported from index.ts) and is
 * matched on `kind`, so each is constructed here and asserted on its shape.
 */

import { describe, it, expect } from "vitest";
import {
    ConnectionClosedError,
    FlowControlError,
    FrameParseError,
    HandshakeTimeoutError,
    PacketParseError,
    QuicError,
    ResetStreamError,
    StopSendingError,
    TransportParameterError,
} from "../src/errors.js";

describe("QuicError", () => {
    it("can be instantiated directly as the base class", () => {
        const cause = new Error("underlying");
        const err = new QuicError("boom", { cause });
        expect(err).toBeInstanceOf(Error);
        expect(err.name).toBe("QuicError");
        expect(err.kind).toBe("QuicError");
        expect(err.message).toBe("boom");
        expect(err.cause).toBe(cause);
    });

    it("sets name from the subclass and stores the cause", () => {
        const cause = new Error("underlying");
        const err = new ConnectionClosedError(0x00n, "bye", { cause });
        expect(err).toBeInstanceOf(Error);
        expect(err.name).toBe("ConnectionClosedError");
        expect(err.kind).toBe("ConnectionClosedError");
        expect(err.cause).toBe(cause);
        expect(err.errorCode).toBe(0x00n);
        expect(err.reason).toBe("bye");
        expect(err.frameType).toBeUndefined();
    });

    it("carries the optional frameType on a connection close", () => {
        const err = new ConnectionClosedError(0x01n, "bad", { frameType: 0x1cn });
        expect(err.frameType).toBe(0x1cn);
        expect(err.message).toContain("errorCode=1");
    });
});

describe("StopSendingError", () => {
    it("records stream id and error code", () => {
        const err = new StopSendingError(4n, 0x02n);
        expect(err.name).toBe("StopSendingError");
        expect(err.kind).toBe("StopSendingError");
        expect(err.streamId).toBe(4n);
        expect(err.errorCode).toBe(0x02n);
        expect(err.message).toContain("STOP_SENDING");
    });
});

describe("ResetStreamError", () => {
    it("records stream id, error code and final size", () => {
        const err = new ResetStreamError(0n, 0x01n, 42n);
        expect(err.name).toBe("ResetStreamError");
        expect(err.kind).toBe("ResetStreamError");
        expect(err.streamId).toBe(0n);
        expect(err.errorCode).toBe(0x01n);
        expect(err.finalSize).toBe(42n);
    });
});

describe("FlowControlError", () => {
    it("reports a connection-level violation when streamId is omitted", () => {
        const err = new FlowControlError(100n, 120n);
        expect(err.name).toBe("FlowControlError");
        expect(err.kind).toBe("FlowControlError");
        expect(err.limit).toBe(100n);
        expect(err.attempted).toBe(120n);
        expect(err.streamId).toBeUndefined();
        expect(err.message).toContain("connection");
    });

    it("reports a per-stream violation when streamId is given", () => {
        const err = new FlowControlError(100n, 120n, 7n);
        expect(err.streamId).toBe(7n);
        expect(err.message).toContain("stream 7");
    });
});

describe("PacketParseError", () => {
    it("records the offset where parsing failed", () => {
        const err = new PacketParseError(9);
        expect(err.name).toBe("PacketParseError");
        expect(err.kind).toBe("PacketParseError");
        expect(err.offset).toBe(9);
        expect(err.message).toContain("offset 9");
    });
});

describe("FrameParseError", () => {
    it("records the offset where parsing failed", () => {
        const err = new FrameParseError(3, { cause: new Error("x") });
        expect(err.name).toBe("FrameParseError");
        expect(err.kind).toBe("FrameParseError");
        expect(err.offset).toBe(3);
        expect(err.cause?.message).toBe("x");
    });
});

describe("TransportParameterError", () => {
    it("records the offending parameter id", () => {
        const err = new TransportParameterError(0x0fn);
        expect(err.name).toBe("TransportParameterError");
        expect(err.kind).toBe("TransportParameterError");
        expect(err.parameter).toBe(0x0fn);
        expect(err.message).toContain("0xf");
    });
});

describe("HandshakeTimeoutError", () => {
    it("records the configured timeout", () => {
        const err = new HandshakeTimeoutError(10_000);
        expect(err.name).toBe("HandshakeTimeoutError");
        expect(err.kind).toBe("HandshakeTimeoutError");
        expect(err.timeoutMs).toBe(10_000);
        expect(err.message).toContain("10000ms");
    });
});

describe("error cause propagation", () => {
    // Every error class accepts an optional `cause`; this exercises the
    // `options?.cause` branch where the cause IS provided (the short-circuit
    // case, options omitted, is covered by the per-class tests above).
    it("propagates the cause through each error type", () => {
        const cause = new Error("root");

        expect(new StopSendingError(4n, 0x02n, { cause }).cause).toBe(cause);
        expect(new ResetStreamError(0n, 0x01n, 42n, { cause }).cause).toBe(cause);
        expect(new FlowControlError(100n, 120n, undefined, { cause }).cause).toBe(cause);
        expect(new PacketParseError(9, { cause }).cause).toBe(cause);
        expect(new TransportParameterError(0x0fn, { cause }).cause).toBe(cause);
        expect(new HandshakeTimeoutError(10_000, { cause }).cause).toBe(cause);
    });
});
