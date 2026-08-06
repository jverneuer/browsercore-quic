/**
 * Bridges a QUIC bidirectional stream to the TLS Transport interface.
 *
 * @browsercore/tls's handshake driver reads and writes TLS records over a
 * `Transport` (a reliable ordered byte stream). QUIC carries TLS handshake
 * bytes inside CRYPTO frames on a single bidirectional stream (stream 0 for
 * the client). This adapter implements the `Transport` interface on top of a
 * `QuicStream` so the existing TLS handshake driver runs unchanged over QUIC.
 *
 * The TLS `Transport` interface is an EventEmitter with `read`, `write`, and
 * `close` methods, plus `id` and `state` fields. QUIC streams expose the same
 * three operations; the adapter is a thin wiring layer that adds the minimal
 * EventEmitter + `id`/`state` surface the handshake driver's record framer
 * requires.
 *
 * Read semantics: TLS's record-layer framer pulls bytes incrementally with
 * `transport.read()` and buffers what it doesn't immediately consume. QUIC's
 * `QuicStream.read()` returns the next reassembled chunk (which may be any
 * size — STREAM frames can be any length). The adapter reads chunks and drains
 * them byte-by-byte via an internal buffer so the TLS record framer sees a
 * smooth byte stream.
 */

import { EventEmitter } from "node:events";
import type { QuicStream } from "../types.js";
import type { CloseReason, TransportId, TransportState } from "@browsercore/transport";

/**
 * Adapt a QUIC bidirectional stream into a TLS `Transport`.
 *
 * @param stream The QUIC bidirectional stream carrying TLS handshake bytes
 *               (stream 0 for the client, per RFC 9000 §2.1).
 * @returns An EventEmitter that also implements `read`, `write`, `close`,
 *          with `id` and `state` for the TLS `Transport` interface.
 */
export function adaptQuicStreamToTransport(stream: QuicStream): QuicTransportAdapter {
    return new QuicTransportAdapter(stream);
}

/**
 * Concrete adapter. QuicStream is NOT an EventEmitter, so we extend EventEmitter
 * to satisfy the `Transport` interface and bridge the stream's read/write/close
 * to it. The TLS handshake driver uses read/write/close and the `id`/`state`
 * fields, so those are provided; events are never subscribed to.
 */
export class QuicTransportAdapter extends EventEmitter {
    /** The underlying QUIC stream. */
    private readonly stream: QuicStream;
    /** True once close() has been called. */
    private closed = false;
    /** Chunks read from the QUIC stream that haven't been consumed by TLS yet. */
    private readonly pending: Uint8Array[] = [];
    /** A reader waiting for the next chunk from the QUIC stream. */
    private waitingReader: ((chunk: Uint8Array) => void) | undefined;
    /** A reader that was rejected (stream closed) — read() should reject. */
    private waitingReject: ((err: Error) => void) | undefined;

    public readonly id: TransportId;
    public readonly state: TransportState;

    public constructor(stream: QuicStream) {
        super();
        this.stream = stream;
        this.id = `quic-stream-${stream.id}` as TransportId;
        this.state = { state: "open" };
    }

    /**
     * Read the next chunk of bytes from the QUIC stream.
     *
     * The TLS record-layer framer calls this repeatedly; each call returns the
     * next reassembled chunk (which may be smaller or larger than a TLS record
     * — the framer buffers internally). Resolves with an empty Uint8Array when
     * the stream has reached its FIN (TLS treats that as a transport-level close).
     */
    public read(): Promise<Uint8Array> {
        if (this.closed) {
            return Promise.reject(new Error("quic transport adapter is closed"));
        }
        // If we have buffered chunks, return the next one.
        const next = this.pending.shift();
        if (next !== undefined) {
            return Promise.resolve(next);
        }
        // Otherwise, pull the next chunk from the QUIC stream and buffer it.
        return new Promise<Uint8Array>((resolve, reject) => {
            this.waitingReader = resolve;
            this.waitingReject = reject;
            void this.readNextChunk();
        });
    }

    /** Pull the next chunk from the QUIC stream and dispatch to the waiting reader. */
    private async readNextChunk(): Promise<void> {
        try {
            const chunk = await this.stream.read();
            if (this.waitingReader === undefined) {
                // We were already rejected (closed) — buffer the chunk
                // (it's actually a no-op in practice because we're closing).
                this.pending.push(chunk);
                return;
            }
            const reader = this.waitingReader;
            this.waitingReader = undefined;
            this.waitingReject = undefined;
            // An empty chunk signals FIN on the QUIC stream — the TLS
            // transport layer treats that as end-of-stream.
            reader(chunk);
        } catch (err) {
            if (this.waitingReject === undefined) {
                return;
            }
            const rejecter = this.waitingReject;
            this.waitingReader = undefined;
            this.waitingReject = undefined;
            rejecter(err as Error);
        }
    }

    /**
     * Write bytes to the QUIC stream. Resolves when the QUIC layer has accepted
     * the bytes (buffered, not necessarily on the wire).
     */
    public write(data: Uint8Array): Promise<void> {
        if (this.closed) {
            return Promise.reject(new Error("quic transport adapter is closed"));
        }
        return this.stream.write(data);
    }

    /**
     * Close the QUIC stream (sends FIN / RESET_STREAM depending on the stream
     * state). Rejects any in-flight read so the TLS record framer surfaces the
     * close promptly.
     */
    public close(_reason?: CloseReason): Promise<void> {
        if (this.closed) {
            return Promise.resolve();
        }
        this.closed = true;
        const rejecter = this.waitingReject;
        if (rejecter !== undefined) {
            this.waitingReader = undefined;
            this.waitingReject = undefined;
            rejecter(new Error("quic transport closed"));
        }
        return this.stream.close();
    }
}
