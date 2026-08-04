/**
 * QUIC connection lifecycle + datagram read loop (RFC 9000 §5, §12).
 *
 * Wires packet header parsing/serialization, the frame layer, and the stream
 * manager over an injected {@link DatagramTransport} (UDP). The connection owns
 * the read loop: it turns inbound datagrams into frames, dispatches each to the
 * stream manager, and drains pending stream sends back into outbound packets.
 *
 * Honest limitations:
 *   - The TLS 1.3 handshake and packet protection (header protection + AEAD
 *     payload encryption) are out of scope. `connectQuic()` returns a connection
 *     that moves *unprotected* frames over the transport directly — enough to
 *     drive the data plane and to be tested with a fake datagram transport. A
 *     production build layers protection + the handshake on top of this.
 *   - No congestion controller, no connection migration, no PATH_CHALLENGE /
 *     PATH_RESPONSE beyond frame relay, and no liveness PING.
 *
 * Concurrency model: the read loop is a single async task pulling datagrams from
 * the transport. Outbound frames are produced synchronously by the stream
 * manager and packed into packets; writes resolve once bytes are buffered.
 */

import type { EventEmitter } from "node:events";
import {
    QuicFrameType,
    type ConnectionId,
    type QuicConnection,
    type QuicFrame,
    type QuicOptions,
    type QuicStream,
    type QuicTransportParameters,
    type UdpAddress,
} from "./types.js";
import { parsePacketHeader, serializeShortHeader, type PacketHeader } from "./packet/packet.js";
import { readFrames, serializeFrame } from "./frame/frame.js";
import { ConnectionClosedError } from "./errors.js";
import { createStreamManager, type StreamManager } from "./stream/stream.js";
import { concatAll } from "./utils.js";

/** Byte type alias matching the `Uint8Array<ArrayBufferLike>` wire signatures. */
type Bytes = Uint8Array;

/** Largest UDP payload we will pack into a single datagram (RFC 9000 §14). */
const MAX_DATAGRAM_PAYLOAD = 1200;

/**
 * Concrete QUIC connection. The public surface matches the fixed
 * `QuicConnection` interface; internal state is kept on the instance.
 */
export class QuicConnectionImpl implements QuicConnection {
    public readonly id: string;

    /** The underlying datagram (UDP) transport. */
    private readonly transport: QuicOptions["transport"];
    /** The peer's UDP address. */
    private readonly peer: UdpAddress;
    /** Stream manager (also an EventEmitter for connection-level signals). */
    private readonly manager: StreamManager & EventEmitter;
    /** Our current destination connection id (the one we put on outbound packets). */
    private readonly dcid: ConnectionId;

    /** Set once the connection begins graceful shutdown. */
    private closing = false;
    /** Set once the connection is fully torn down. */
    private closed = false;
    /** Buffered outbound frames waiting to be packed into the next packet. */
    private readonly outboundFrames: QuicFrame[] = [];

    public constructor(
        id: string,
        options: QuicOptions,
        manager: StreamManager & EventEmitter,
        dcid: ConnectionId,
    ) {
        this.id = id;
        this.transport = options.transport;
        this.peer = options.peer;
        this.manager = manager;
        this.dcid = dcid;
    }

    // --- public QuicConnection surface ------------------------------------------

    public openBidirectionalStream(): Promise<QuicStream> {
        return Promise.resolve().then(() => {
            this.ensureOpen();
            return this.manager.openStream(true);
        });
    }

    public acceptBidirectionalStream(): Promise<QuicStream> {
        return Promise.resolve().then(() => {
            this.ensureOpen();
            return this.manager.acceptStream(true);
        });
    }

    public openUnidirectionalStream(): Promise<QuicStream> {
        return Promise.resolve().then(() => {
            this.ensureOpen();
            return this.manager.openStream(false);
        });
    }

    public acceptUnidirectionalStream(): Promise<QuicStream> {
        return Promise.resolve().then(() => {
            this.ensureOpen();
            return this.manager.acceptStream(false);
        });
    }

    public async close(errorCode: bigint, reason: string): Promise<void> {
        if (this.closed) {
            return;
        }
        this.closing = true;
        this.manager.close(errorCode, reason);
        // Pack + flush the CONNECTION_CLOSE frame, then tear down.
        await this.flush();
        await this._teardown({ kind: "client_close" });
    }

    // --- frame I/O -------------------------------------------------------------

    /**
     * Enqueue a frame for the next outbound packet. Control frames from the
     * stream manager flow through here so they are serialized + sent by the
     * connection's packetizer.
     */
    public sendFrame(frame: QuicFrame): void {
        this.outboundFrames.push(frame);
    }

    /**
     * Pack all buffered outbound frames into a short-header packet and send it.
     * Splits into multiple datagrams if the payload exceeds MAX_DATAGRAM_PAYLOAD.
     */
    private async flush(): Promise<void> {
        if (this.outboundFrames.length === 0) {
            return;
        }
        const frames = this.outboundFrames.splice(0);
        const payload = this.packFrames(frames);
        let offset = 0;
        while (offset < payload.length) {
            const slice = payload.subarray(offset, offset + MAX_DATAGRAM_PAYLOAD) as Bytes;
            const packet = this.wrapPacket(slice);
            // eslint-disable-next-line no-await-in-loop — datagrams must be sent in order; coalescing handled by kernel
            await this.transport.send(packet, this.peer);
            offset += MAX_DATAGRAM_PAYLOAD;
        }
    }

    /** Serialize frames into a single byte buffer (no packet header). */
    private packFrames(frames: QuicFrame[]): Bytes {
        return concatAll(frames.map((f) => serializeFrame(f)));
    }

    /** Wrap a serialized payload in a short (1-RTT) header + packet number. */
    private wrapPacket(payload: Bytes): Bytes {
        const header = serializeShortHeader(this.dcid, 1, false, false);
        // 1-byte packet number (relative offset 0) — placeholder for the
        // protection layer, which assigns real packet numbers.
        const packetNumber = new Uint8Array([0]);
        return concatAll([header, packetNumber, payload]);
    }

    // --- read loop -------------------------------------------------------------

    /**
     * Start the datagram read loop. Must be called once after construction.
     * Runs until the transport closes or the connection tears down.
     */
    public startReadLoop(): void {
        // React to connection-level signals from the stream manager.
        this.manager.on("connectionClose", ({ errorCode, reason }: { errorCode: bigint; reason: string }) => {
            void this.onPeerClose(errorCode, reason);
        });

        void this.readLoop();
    }

    private async onPeerClose(errorCode: bigint, reason: string): Promise<void> {
        if (this.closed) {
            return;
        }
        this.closing = true;
        this.manager.abortAll(new ConnectionClosedError(errorCode, reason));
        await this._teardown({ kind: "remote_close" });
    }

    /** Parse a single datagram into frames and dispatch them. */
    private async dispatchDatagram(data: Bytes): Promise<void> {
        if (data.length === 0) {
            return;
        }
        try {
            const header = parsePacketHeader(data);
            this.applyHeader(header);
            // Skip the header + packet number to reach the frame payload. The
            // protection layer would decrypt first in a full implementation.
            const pnLength = header.packetNumberLength;
            // Short headers carry a variable-length DCID after the first byte;
            // its length is not on the wire, so the connection supplies it from
            // the handshake state we already know (this.dcid).
            const dcidLength = header.form === 0 ? this.dcid.length : 0;
            const payloadStart = header.headerLength + dcidLength + pnLength;
            const payload = data.subarray(payloadStart);
            if (payload.length === 0) {
                return;
            }

            const read = this.byteStreamReader(payload);
            for await (const frame of readFrames(read)) {
                this.handleFrame(frame);
            }
        } catch (err) {
            // A parse error on one datagram is not necessarily fatal for the
            // connection, but without a protection layer to frame it we close.
            this._handleFatal(err instanceof Error ? err : new Error(String(err)));
        }
    }

    /** Pull the DCID / version from a parsed header into connection state. */
    private applyHeader(header: PacketHeader): void {
        if (header.form === 1) {
            // Long header: could carry a version negotiation. We ignore for now.
            return;
        }
        // Short header: the DCID on the wire is the route to the peer.
        void header.dcid;
    }

    /**
     * Build a pull-based byte reader over a fixed buffer. `readFrames` consumes
     * bytes incrementally; this yields slices until the buffer is exhausted.
     */
    private byteStreamReader(buf: Bytes): () => Promise<Uint8Array | null> {
        let offset = 0;
        return (): Promise<Uint8Array | null> => {
            if (offset >= buf.length) {
                return Promise.resolve(null);
            }
            const chunk = buf.subarray(offset);
            offset = buf.length;
            return Promise.resolve(chunk);
        };
    }

    /** Route a decoded frame: data-plane frames to the manager, the rest here. */
    private handleFrame(frame: QuicFrame): void {
        // Connection / handshake layer concerns (PADDING, PING, ACK, CRYPTO,
        // NEW_TOKEN, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, PATH_CHALLENGE,
        // PATH_RESPONSE, HANDSHAKE_DONE) — relay only. Data-plane frames are
        // dispatched to the stream manager, which may emit outbound control
        // frames (MAX_DATA, MAX_STREAM_DATA, ...).
        switch (frame.type) {
            case QuicFrameType.RESET_STREAM:
            case QuicFrameType.STOP_SENDING:
            case QuicFrameType.STREAM:
            case QuicFrameType.MAX_DATA:
            case QuicFrameType.MAX_STREAM_DATA:
            case QuicFrameType.MAX_STREAMS_BIDI:
            case QuicFrameType.MAX_STREAMS_UNI:
            case QuicFrameType.DATA_BLOCKED:
            case QuicFrameType.STREAM_DATA_BLOCKED:
            case QuicFrameType.STREAMS_BLOCKED_BIDI:
            case QuicFrameType.STREAMS_BLOCKED_UNI:
            case QuicFrameType.CONNECTION_CLOSE:
            case QuicFrameType.CONNECTION_CLOSE_APP:
                this.withOutbound(() => {
                    this.manager.dispatch(frame);
                });
                break;
            // Connection / handshake layer concerns — relay only. The data plane
            // does not act on these; a full implementation would pace ACKs and
            // handle the handshake, which is out of scope here.
            case QuicFrameType.PADDING:
            case QuicFrameType.PING:
            case QuicFrameType.ACK:
            case QuicFrameType.ACK_ECN:
            case QuicFrameType.CRYPTO:
            case QuicFrameType.NEW_TOKEN:
            case QuicFrameType.NEW_CONNECTION_ID:
            case QuicFrameType.RETIRE_CONNECTION_ID:
            case QuicFrameType.PATH_CHALLENGE:
            case QuicFrameType.PATH_RESPONSE:
            case QuicFrameType.HANDSHAKE_DONE:
                break;
        }
    }

    /** Run `fn`, then flush any outbound frames it produced to the peer. */
    private withOutbound(fn: () => void): void {
        const before = this.outboundFrames.length;
        fn();
        if (this.outboundFrames.length > before) {
            void this.flush();
        }
    }

    /** Main read loop: pull datagrams, dispatch, drain sends. */
    private async readLoop(): Promise<void> {
        try {
            while (!this.closed) {
                // eslint-disable-next-line no-await-in-loop — QUIC read loop: datagrams must be dispatched in arrival order
                const { data } = await this.transport.recv();
                // eslint-disable-next-line no-await-in-loop — QUIC read loop: each datagram must be processed before the next
                await this.dispatchDatagram(data as Bytes);
                // Drain any pending stream sends after handling each datagram.
                this.drainSends();
            }
        } catch (err) {
            if (!this.closed) {
                this._handleFatal(err instanceof Error ? err : new Error(String(err)));
            }
        }
    }

    /** Emit STREAM frames for streams with queued data, then flush. */
    private drainSends(): void {
        if (!this.manager.hasPendingSends) {
            return;
        }
        this.manager.flushSends(MAX_DATAGRAM_PAYLOAD, (frame) => {
            this.sendFrame(frame);
        });
        void this.flush();
    }

    /** Tear down the connection on a fatal transport / parse error. */
    private _handleFatal(err: Error): void {
        if (this.closed) {
            return;
        }
        this.closing = true;
        this.manager.abortAll(err);
        void this._teardown({ kind: "error", error: err });
    }

    /** Mark closed and release the transport. */
    private async _teardown(reason: { readonly kind: "client_close" } | { readonly kind: "remote_close" } | { readonly kind: "error"; readonly error: Error }): Promise<void> {
        if (this.closed) {
            return;
        }
        this.closed = true;
        this.closing = true;
        try {
            await this.transport.close(reason);
        } catch {
            // best-effort
        }
    }

    private ensureOpen(): void {
        if (this.closing || this.closed) {
            throw new Error("connection is closing");
        }
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/** Resolve the local transport parameters, filling in defaults. */
function resolveLocalParameters(options: QuicOptions): QuicTransportParameters {
    const src = options.transportParameters;
    const out: Partial<Record<keyof QuicTransportParameters, bigint | number>> = {};
    if (src?.initialMaxData !== undefined) {
        out.initialMaxData = src.initialMaxData;
    }
    if (src?.initialMaxStreamDataBidiLocal !== undefined) {
        out.initialMaxStreamDataBidiLocal = src.initialMaxStreamDataBidiLocal;
    }
    if (src?.initialMaxStreamDataBidiRemote !== undefined) {
        out.initialMaxStreamDataBidiRemote = src.initialMaxStreamDataBidiRemote;
    }
    if (src?.initialMaxStreamDataUni !== undefined) {
        out.initialMaxStreamDataUni = src.initialMaxStreamDataUni;
    }
    if (src?.initialMaxStreamsBidi !== undefined) {
        out.initialMaxStreamsBidi = src.initialMaxStreamsBidi;
    }
    if (src?.initialMaxStreamsUni !== undefined) {
        out.initialMaxStreamsUni = src.initialMaxStreamsUni;
    }
    if (src?.maxIdleTimeoutMs !== undefined) {
        out.maxIdleTimeoutMs = src.maxIdleTimeoutMs;
    }
    if (src?.maxUdpPayloadSize !== undefined) {
        out.maxUdpPayloadSize = src.maxUdpPayloadSize;
    }
    if (src?.activeConnectionIdLimit !== undefined) {
        out.activeConnectionIdLimit = src.activeConnectionIdLimit;
    }
    return out as QuicTransportParameters;
}

// ---------------------------------------------------------------------------
// connectQuic
// ---------------------------------------------------------------------------

/**
 * Establish a QUIC connection over an existing datagram transport.
 *
 * Creates the stream manager and the read loop. Because the TLS handshake and
 * packet protection are out of scope, this returns a connection that moves
 * unprotected frames — the data plane is fully functional and testable with a
 * fake datagram transport.
 */
export function connectQuic(options: QuicOptions): Promise<QuicConnection> {
    const id = `quic_${Date.now().toString(36)}`;

    // The stream manager is constructed before the connection, but its frames
    // must reach the connection's packetizer. We bridge the two with a mutable
    // router that we point at the connection once it exists.
    const frameRouter: { send: (frame: QuicFrame) => void } = { send: () => {} };

    const manager = createStreamManager({
        sendFrame: (frame) => {
            frameRouter.send(frame);
        },
        localParameters: resolveLocalParameters(options),
        peerParameters: options.transportParameters ?? {},
    });

    const conn = new QuicConnectionImpl(id, options, manager, options.initialDcid);
    frameRouter.send = (frame) => {
        conn.sendFrame(frame);
    };

    // A larger send window may have queued stream data — the read loop drains it.
    manager.on("maxData", () => { /* sends drain in the read loop */ });

    conn.startReadLoop();
    return Promise.resolve(conn);
}
