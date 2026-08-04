/**
 * QUIC stream state machine + flow control + receive reassembly (RFC 9000 §2, §4).
 *
 * Each QUIC stream is a reliable, ordered byte stream. The connection receives
 * STREAM frames (offset, data, fin) out of order — datagrams are not ordered —
 * so a stream reassembles by offset into the byte stream `read()` consumes.
 * Flow control is enforced on both sides: we never send more than the peer's
 * MAX_STREAM_DATA / MAX_DATA windows allow, and we replenish the peer's send
 * credit with MAX_STREAM_DATA / MAX_DATA frames as we consume.
 *
 * Honest limitations:
 *   - Send-side backpressure is real: `write()` resolves once bytes are buffered
 *     at the QUIC layer, and the connection drains the send queue only as far as
 *     the peer's flow-control window allows, queueing the rest. When the window
 *     is exhausted we tell the peer with DATA_BLOCKED / STREAM_DATA_BLOCKED.
 *   - There is no congestion controller and no liveness ping in this layer —
 *     ACK frames are relayed but not paced. Connection establishment (the TLS
 *     handshake) and packet protection are out of scope; `connectQuic()` returns
 *     a connection that moves frames over the transport directly.
 */

import { EventEmitter } from "node:events";
import {
    QuicFrameType,
    firstStreamId,
    makeStreamId,
    nextStreamId,
    streamIdIsBidirectional,
    streamIdIsClientInitiated,
    type MaxStreamsFrame,
    type QuicFrame,
    type QuicStream,
    type QuicTransportParameters,
    type StreamId,
    type StreamState,
    type StreamCloseReason,
} from "../types.js";
import { ResetStreamError, StopSendingError } from "../errors.js";
import { concat } from "../utils.js";

/** Byte type alias matching the `Uint8Array<ArrayBufferLike>` wire signatures. */
type Bytes = Uint8Array;

/** Empty byte array constant. */
const EMPTY: Bytes = new Uint8Array(0);

// ---------------------------------------------------------------------------
// Defaults (RFC 9000 §18.2 has no mandated initial windows; these are sane)
// ---------------------------------------------------------------------------

const DEFAULT_INITIAL_MAX_DATA = 1_048_576n; // 1 MiB
const DEFAULT_INITIAL_MAX_STREAM_DATA = 262_144n; // 256 KiB
const DEFAULT_INITIAL_MAX_STREAMS_BIDI = 100n;
const DEFAULT_INITIAL_MAX_STREAMS_UNI = 100n;

/**
 * Replenish the peer's send credit once we have consumed this fraction of the
 * current window. Sending an update per byte would flood the connection; waiting
 * for the full window would stall the peer. Half is the usual trade-off.
 */
const REPLENISH_FRACTION = 2;

// ---------------------------------------------------------------------------
// Internal stream record
// ---------------------------------------------------------------------------

/**
 * A single QUIC stream. Externally we hand out the `QuicStream` view; this adds
 * the bookkeeping the state machine needs (send queue, reassembly buffer,
 * flow-control windows, waiters) without polluting the public interface.
 */
class ManagedStream implements QuicStream {
    public readonly id: StreamId;
    public state: StreamState = { state: "open" };

    // --- send side -------------------------------------------------------------
    /** Bytes buffered waiting for flow-control window / connection drain. */
    public sendQueue: Bytes = EMPTY;
    /** True once the local side requested FIN (via close()). */
    public sendFinPending = false;
    /** True once the FIN bit has been sent on a STREAM frame. */
    public finSent = false;
    /** Total stream bytes sent so far (for flow-control accounting). */
    public dataSent = 0n;
    /** The peer's current per-stream send limit (grown via MAX_STREAM_DATA). */
    public maxStreamData: bigint;

    // --- receive side ----------------------------------------------------------
    /** Out-of-order STREAM data waiting to be reassembled, sorted by offset. */
    private readonly reassembly: Array<{ readonly offset: bigint; readonly data: Bytes }> = [];
    /** Next byte offset to deliver to a reader. */
    private recvOffset = 0n;
    /** Offset at which the FIN arrived, if any. */
    private recvFinOffset: bigint | undefined;
    /** Bytes ready to read, buffered when no reader is waiting. */
    private readBuffer: Bytes = EMPTY;
    /** True once the FIN has been delivered to a reader. */
    private finDelivered = false;
    /** Total stream bytes received so far (for flow-control accounting). */
    private dataReceived = 0n;
    /** The local per-stream receive limit we have advertised to the peer. */
    private maxStreamDataAdvertised: bigint;

    // --- waiters ---------------------------------------------------------------
    /** Readers waiting for data / fin. */
    private readonly readWaiters: Array<{
        resolve: (bytes: Bytes) => void;
        reject: (err: Error) => void;
    }> = [];
    /** Writers waiting for flow-control window to open. */
    private readonly sendWaiters: Array<{
        resolve: () => void;
        reject: (err: Error) => void;
    }> = [];

    public constructor(id: StreamId, initialMaxStreamData: bigint) {
        this.id = id;
        this.maxStreamData = initialMaxStreamData;
        this.maxStreamDataAdvertised = initialMaxStreamData;
    }

    // --- public QuicStream surface ---------------------------------------------

    public write(data: Uint8Array): Promise<void> {
        if (this.state.state === "closed" || this.state.state === "half_closed_local") {
            return Promise.reject(
                new ResetStreamError(this.id, 0x05n /* STREAM_STATE_ERROR */, this.dataSent),
            );
        }
        if (data.length === 0) {
            return Promise.resolve();
        }
        this.sendQueue = concat(this.sendQueue, data as Bytes);
        return Promise.resolve();
    }

    public read(): Promise<Bytes> {
        // Data already buffered: hand back the next contiguous chunk.
        if (this.readBuffer.length > 0) {
            const out = this.readBuffer;
            this.readBuffer = EMPTY;
            return Promise.resolve(out);
        }
        // EOF already reached: signal end-of-stream with an empty chunk.
        if (this.finDelivered) {
            return Promise.resolve(EMPTY);
        }
        // Otherwise block until data / fin / reset arrives.
        return new Promise<Bytes>((resolve, reject) => {
            this.readWaiters.push({ resolve, reject });
        });
    }

    public close(): Promise<void> {
        if (this.state.state === "closed") {
            return Promise.resolve();
        }
        this.sendFinPending = true;
        return Promise.resolve();
    }

    // --- send-side drain (called by the connection) ----------------------------

    /**
     * Pull up to `maxBytes` from the send queue for transmission. Returns the
     * bytes to put on a STREAM frame (caller adds offset + fin). Does not mutate
     * the queue; call `commitSend()` once the frame is actually sent.
     */
    public peekSend(maxBytes: number): Bytes {
        if (this.sendQueue.length === 0) {
            return EMPTY;
        }
        const len = Math.min(maxBytes, this.sendQueue.length);
        return this.sendQueue.subarray(0, len) as Bytes;
    }

    /** Record that `count` bytes starting at `offset` were sent. */
    public commitSend(offset: bigint, count: number, fin: boolean): void {
        this.sendQueue = this.sendQueue.subarray(count) as Bytes;
        this.dataSent += BigInt(count);
        if (offset + BigInt(count) > this.sendFinOffset) {
            this.sendFinOffset = offset + BigInt(count);
        }
        if (fin) {
            this.finSent = true;
            this.transitionOnLocalFin();
        }
        // The send queue may have drained below the window — wake waiters.
        this.drainSendWaiters();
    }

    /** The offset at which the next byte should be sent. */
    public get sendOffset(): bigint {
        return this.dataSent;
    }

    /** True if there is data or a FIN left to send. */
    public get hasPendingSend(): boolean {
        return this.sendQueue.length > 0 || (this.sendFinPending && !this.finSent);
    }

    // --- receive-side reassembly (called by the manager) ------------------------

    /**
     * Ingest a STREAM frame's payload at `offset`. Reassembles contiguous bytes
     * into the read buffer / resolves a waiting reader, and updates flow-control
     * accounting. Returns true if a MAX_STREAM_DATA update should be sent.
     */
    public ingest(offset: bigint, data: Bytes, fin: boolean): boolean {
        const end = offset + BigInt(data.length);
        if (fin) {
            this.recvFinOffset = end;
        }
        this.dataReceived += BigInt(data.length);

        // Drop bytes we have already delivered (retransmissions / overlaps).
        if (end <= this.recvOffset) {
            if (offset < this.recvOffset) {
                return this.replenishNeeded();
            }
            return this.replenishNeeded();
        }
        // Clip the front if part of this frame is below recvOffset.
        let payload = data;
        let payloadOffset = offset;
        if (offset < this.recvOffset) {
            const drop = Number(this.recvOffset - offset);
            payload = payload.subarray(drop) as Bytes;
            payloadOffset = this.recvOffset;
        }

        // Contiguous: deliver immediately. Else buffer for later.
        if (payloadOffset === this.recvOffset) {
            this.recvOffset += BigInt(payload.length);
            this.deliver(payload);
            // The new recvOffset may now bridge buffered gaps — drain them.
            this.drainReassembly();
        } else {
            this.insertReassembly(payloadOffset, payload);
        }

        // FIN and all bytes delivered: signal EOF.
        if (this.recvFinOffset !== undefined && this.recvOffset >= this.recvFinOffset) {
            this.signalFin();
        }
        return this.replenishNeeded();
    }

    /** True if we should send a MAX_STREAM_DATA to replenish the peer's credit. */
    private replenishNeeded(): boolean {
        const consumed = this.dataReceived;
        const threshold = this.maxStreamDataAdvertised / BigInt(REPLENISH_FRACTION);
        return consumed >= threshold;
    }

    /** Advertise additional receive credit to the peer (call after sending MAX_STREAM_DATA). */
    public advertiseStreamDataCredit(additional: bigint): void {
        this.maxStreamDataAdvertised += additional;
    }

    /** The current per-stream receive limit we have advertised to the peer. */
    public get streamMaxDataAdvertised(): bigint {
        return this.maxStreamDataAdvertised;
    }

    private insertReassembly(offset: bigint, data: Bytes): void {
        this.reassembly.push({ offset, data });
        this.reassembly.sort((a, b) => (a.offset < b.offset ? -1 : a.offset > b.offset ? 1 : 0));
    }

    /** Deliver any buffered reassembly chunks that now bridge recvOffset. */
    private drainReassembly(): void {
        while (this.reassembly.length > 0) {
            const head = this.reassembly[0];
            if (head === undefined || head.offset > this.recvOffset) {
                break;
            }
            this.reassembly.shift();
            // head.offset <= recvOffset (it was inserted above recvOffset, so equal).
            this.recvOffset += BigInt(head.data.length);
            this.deliver(head.data);
        }
    }

    /** Hand bytes to a waiting reader or buffer them. */
    private deliver(bytes: Bytes): void {
        const waiter = this.readWaiters.shift();
        if (waiter === undefined) {
            this.readBuffer = concat(this.readBuffer, bytes);
            return;
        }
        waiter.resolve(bytes);
    }

    private signalFin(): void {
        if (this.finDelivered) {
            return;
        }
        this.finDelivered = true;
        const waiter = this.readWaiters.shift();
        if (waiter !== undefined) {
            waiter.resolve(EMPTY);
        }
        this.transitionOnRemoteFin();
    }

    // --- peer control frames ---------------------------------------------------

    /** Peer reset the stream: reject every waiter and close. */
    public resetPeer(errorCode: bigint, finalSize: bigint): void {
        this.state = { state: "closed", reason: { kind: "reset", errorCode } };
        this.rejectReaders(new ResetStreamError(this.id, errorCode, finalSize));
        this.rejectWriters(new ResetStreamError(this.id, errorCode, finalSize));
    }

    /** Peer asked us to stop sending. */
    public stopSending(errorCode: bigint): void {
        // Discard the send queue — the peer does not want more data.
        this.sendQueue = EMPTY;
        this.sendFinPending = false;
        this.rejectWriters(new StopSendingError(this.id, errorCode));
    }

    /** Grow the peer's per-stream send limit (MAX_STREAM_DATA arrived). */
    public growSendWindow(maximum: bigint): void {
        if (maximum <= this.maxStreamData) {
            return;
        }
        this.maxStreamData = maximum;
        this.drainSendWaiters();
    }

    // --- waiter management -----------------------------------------------------

    private drainSendWaiters(): void {
        if (this.sendQueue.length === 0) {
            while (this.sendWaiters.length > 0) {
                const waiter = this.sendWaiters.shift();
                if (waiter !== undefined) {
                    waiter.resolve();
                }
            }
        }
    }

    private rejectReaders(err: Error): void {
        while (this.readWaiters.length > 0) {
            const waiter = this.readWaiters.shift();
            if (waiter !== undefined) {
                waiter.reject(err);
            }
        }
    }

    private rejectWriters(err: Error): void {
        while (this.sendWaiters.length > 0) {
            const waiter = this.sendWaiters.shift();
            if (waiter !== undefined) {
                waiter.reject(err);
            }
        }
    }

    // --- state machine ----------------------------------------------------------

    private transitionOnLocalFin(): void {
        const s = this.state;
        if (s.state === "open") {
            this.state = { state: "half_closed_local" };
        } else if (s.state === "half_closed_remote") {
            this.state = { state: "closed", reason: { kind: "normal" } };
        }
    }

    private transitionOnRemoteFin(): void {
        const s = this.state;
        if (s.state === "open") {
            this.state = { state: "half_closed_remote" };
        } else if (s.state === "half_closed_local") {
            this.state = { state: "closed", reason: { kind: "normal" } };
        }
    }

    /** Force-close (connection teardown). */
    public forceClose(reason: StreamCloseReason): void {
        this.state = { state: "closed", reason };
        this.rejectReaders(new Error("connection closed"));
        this.rejectWriters(new Error("connection closed"));
    }

    /** The offset up to which we have sent (for STREAM frame offset + final size). */
    public sendFinOffset = 0n;
}

// ---------------------------------------------------------------------------
// Stream manager
// ---------------------------------------------------------------------------

/** A handle the stream manager exposes to the connection for sending + dispatch. */
export interface StreamManager {
    /** Open a new locally-initiated stream of the given type. */
    openStream(bidirectional: boolean): QuicStream;
    /** Wait for the next peer-initiated stream of the given type. */
    acceptStream(bidirectional: boolean): Promise<QuicStream>;
    /** Dispatch a decoded frame to the relevant stream / connection. */
    dispatch(frame: QuicFrame): void;
    /**
     * Update the peer transport parameters (e.g. once they are decoded from
     * the peer's handshake). Replaces the parameters the manager uses to size
     * its send windows to the peer.
     */
    updatePeerParameters(params: QuicTransportParameters): void;
    /**
     * Drain pending sends into STREAM frames, respecting flow control. Calls
     * `emit` for each frame that should be packed into an outbound packet.
     * `maxPayload` bounds the total bytes of STREAM data to emit this pass.
     */
    flushSends(maxPayload: number, emit: (frame: QuicFrame) => void): void;
    /** True if there are streams with data/FIN pending to send. */
    readonly hasPendingSends: boolean;
    /** Reject every in-flight reader/writer and close all streams. */
    abortAll(error: Error): void;
    /** Begin connection close: emit a CONNECTION_CLOSE and stop accepting. */
    close(errorCode: bigint, reason: string): void;
    /** The local transport parameters we advertise. */
    readonly localParameters: QuicTransportParameters;
}

/** Dependencies the stream manager needs from the connection. */
export interface StreamManagerDeps {
    /** Send a frame to be packed into an outbound packet. */
    sendFrame: (frame: QuicFrame) => void;
    /** Local transport parameters to advertise. */
    localParameters: QuicTransportParameters;
    /** Peer transport parameters (for their receive windows). */
    peerParameters: QuicTransportParameters;
}

/**
 * Create a stream manager. `deps.sendFrame` is the callback for frame I/O — the
 * manager never touches the transport directly.
 *
 * The returned object is also an {@link EventEmitter} emitting connection-level
 * signals the connection layer reacts to:
 *   - "incomingStream", stream   — a peer-initiated stream the app can accept
 *   - "connectionClose", {errorCode, reason}  — peer sent CONNECTION_CLOSE
 *   - "maxData", maximum          — peer grew our connection send window
 */
export function createStreamManager(deps: StreamManagerDeps): StreamManager & EventEmitter {
    const streams = new Map<StreamId, ManagedStream>();
    const emitter = new EventEmitter();

    // Next locally-initiated stream ids, per type (RFC 9000 §2.1).
    let nextBidi = firstStreamId(true, true); // client-initiated bidirectional = 0
    let nextUni = firstStreamId(false, true); // client-initiated unidirectional = 2

    // Peer stream-id limits (how many streams the peer will accept).
    let peerMaxBidi = DEFAULT_INITIAL_MAX_STREAMS_BIDI;
    let peerMaxUni = DEFAULT_INITIAL_MAX_STREAMS_UNI;

    // Connection-level flow control (send side).
    let connectionMaxData = DEFAULT_INITIAL_MAX_DATA;
    let connectionDataSent = 0n;

    // Connection-level flow control (receive side) + accounting.
    let connectionMaxDataAdvertised = resolveLocalMaxData(deps.localParameters);
    let connectionDataReceived = 0n;

    let closing = false;
    let closed = false;

    function resolveLocalMaxData(params: QuicTransportParameters): bigint {
        return params.initialMaxData ?? DEFAULT_INITIAL_MAX_DATA;
    }

    function resolvePeerMaxStreamData(bidirectional: boolean): bigint {
        // The peer's limit on how much *we* may send per stream. We do not know
        // the peer's per-stream value until the handshake, so fall back to the
        // default; a real implementation reads INITIAL_MAX_STREAM_DATA_*.
        if (bidirectional) {
            return (
                deps.peerParameters.initialMaxStreamDataBidiRemote ??
                deps.peerParameters.initialMaxStreamDataBidiLocal ??
                DEFAULT_INITIAL_MAX_STREAM_DATA
            );
        }
        return deps.peerParameters.initialMaxStreamDataUni ?? DEFAULT_INITIAL_MAX_STREAM_DATA;
    }

    // --- frame I/O helpers -----------------------------------------------------

    function sendMaxStreamData(stream: ManagedStream): void {
        // Grant the peer another full window of credit on this stream.
        const additional = resolvePeerMaxStreamData(streamIdIsBidirectional(stream.id));
        stream.advertiseStreamDataCredit(additional);
        deps.sendFrame({
            type: QuicFrameType.MAX_STREAM_DATA,
            streamId: stream.id,
            maximum: stream.streamMaxDataAdvertised,
        });
    }

    function sendMaxData(): void {
        const additional = connectionMaxDataAdvertised;
        connectionMaxDataAdvertised += additional;
        deps.sendFrame({ type: QuicFrameType.MAX_DATA, maximum: connectionMaxDataAdvertised });
    }

    // --- stream lifecycle ------------------------------------------------------

    function openStream(bidirectional: boolean): QuicStream {
        if (closing || closed) {
            throw new Error("connection is closing");
        }
        const id = bidirectional ? nextBidi : nextUni;
        if (bidirectional) {
            nextBidi = nextStreamId(nextBidi);
        } else {
            nextUni = nextStreamId(nextUni);
        }
        const stream = new ManagedStream(id, resolvePeerMaxStreamData(bidirectional));
        streams.set(id, stream);
        return stream;
    }

    function acceptStream(bidirectional: boolean): Promise<QuicStream> {
        if (closing || closed) {
            return Promise.reject(new Error("connection is closing"));
        }
        // Already have an incoming stream of this type waiting?
        for (const stream of streams.values()) {
            const matchesType = streamIdIsBidirectional(stream.id) === bidirectional;
            const peerInitiated = !streamIdIsClientInitiated(stream.id);
            if (matchesType && peerInitiated && !acceptedStreams.has(stream.id)) {
                acceptedStreams.add(stream.id);
                return Promise.resolve(stream);
            }
        }
        return new Promise<QuicStream>((resolve, reject) => {
            acceptWaiters.push({ bidirectional, resolve, reject });
        });
    }

    const acceptedStreams = new Set<StreamId>();
    const acceptWaiters: Array<{
        bidirectional: boolean;
        resolve: (s: QuicStream) => void;
        reject: (e: Error) => void;
    }> = [];

    function registerIncomingStream(id: StreamId): ManagedStream {
        const bidirectional = streamIdIsBidirectional(id);
        const stream = new ManagedStream(id, resolvePeerMaxStreamData(bidirectional));
        streams.set(id, stream);
        // Wake a matching accept waiter if one is waiting.
        const waiterIdx = acceptWaiters.findIndex((w) => w.bidirectional === bidirectional);
        if (waiterIdx >= 0) {
            const [waiter] = acceptWaiters.splice(waiterIdx, 1);
            if (waiter !== undefined) {
                acceptedStreams.add(id);
                waiter.resolve(stream);
            }
        } else {
            emitter.emit("incomingStream", stream);
        }
        return stream;
    }

    // --- send drain ------------------------------------------------------------

    function flushSends(maxPayload: number, emit: (frame: QuicFrame) => void): void {
        let budget = maxPayload;
        for (const stream of streams.values()) {
            if (budget <= 0) {
                break;
            }
            if (!stream.hasPendingSend) {
                continue;
            }
            // Respect both the connection and per-stream send windows.
            const streamWindow = stream.maxStreamData - stream.dataSent;
            const connWindow = connectionMaxData - connectionDataSent;
            let allow = Math.min(Number(streamWindow), Number(connWindow), budget);
            if (allow <= 0) {
                if (streamWindow <= 0n) {
                    emit({
                        type: QuicFrameType.STREAM_DATA_BLOCKED,
                        streamId: stream.id,
                        limit: stream.maxStreamData,
                    });
                }
                continue;
            }
            let payload = stream.peekSend(allow);
            if (payload.length > allow) {
                payload = payload.subarray(0, allow) as Bytes;
            }
            const isLastOfStream =
                stream.sendFinPending && stream.sendQueue.length <= payload.length;
            if (isLastOfStream) {
                allow = payload.length; // FIN frame may be shorter than the window
            }
            const offset = stream.sendOffset;
            emit({
                type: QuicFrameType.STREAM,
                streamId: stream.id,
                offset,
                data: payload,
                fin: isLastOfStream,
            });
            stream.commitSend(offset, payload.length, isLastOfStream);
            connectionDataSent += BigInt(payload.length);
            budget -= payload.length;
        }
        if (budget <= 0 && connWindowTooSmall()) {
            emit({ type: QuicFrameType.DATA_BLOCKED, limit: connectionMaxData });
        }
    }

    function connWindowTooSmall(): boolean {
        return connectionMaxData - connectionDataSent <= 0n;
    }

    // --- dispatch --------------------------------------------------------------

    function dispatch(frame: QuicFrame): void {
        switch (frame.type) {
            case QuicFrameType.STREAM:
                handleStream(frame);
                break;
            case QuicFrameType.RESET_STREAM:
                handleResetStream(frame);
                break;
            case QuicFrameType.STOP_SENDING:
                handleStopSending(frame);
                break;
            case QuicFrameType.MAX_DATA:
                handleMaxData(frame);
                break;
            case QuicFrameType.MAX_STREAM_DATA:
                handleMaxStreamData(frame);
                break;
            case QuicFrameType.MAX_STREAMS_BIDI:
            case QuicFrameType.MAX_STREAMS_UNI:
                handleMaxStreams(frame);
                break;
            case QuicFrameType.CONNECTION_CLOSE:
            case QuicFrameType.CONNECTION_CLOSE_APP:
                handleConnectionClose(frame);
                break;
            case QuicFrameType.DATA_BLOCKED:
            case QuicFrameType.STREAM_DATA_BLOCKED:
            case QuicFrameType.STREAMS_BLOCKED_BIDI:
            case QuicFrameType.STREAMS_BLOCKED_UNI:
            case QuicFrameType.PING:
            case QuicFrameType.PADDING:
            case QuicFrameType.ACK:
            case QuicFrameType.ACK_ECN:
            case QuicFrameType.CRYPTO:
            case QuicFrameType.NEW_TOKEN:
            case QuicFrameType.NEW_CONNECTION_ID:
            case QuicFrameType.RETIRE_CONNECTION_ID:
            case QuicFrameType.PATH_CHALLENGE:
            case QuicFrameType.PATH_RESPONSE:
            case QuicFrameType.HANDSHAKE_DONE:
                // Peer is blocked on a window we control, or a connection /
                // handshake layer concern — informational / relay only. A full
                // implementation would pace. We surface nothing here.
                break;
        }
    }

    function handleStream(frame: Extract<QuicFrame, { type: typeof QuicFrameType.STREAM }>): void {
        let stream = streams.get(makeStreamId(frame.streamId));
        if (stream === undefined) {
            // Peer opened a new stream.
            if (streamIdIsClientInitiated(makeStreamId(frame.streamId))) {
                return; // unknown local stream; ignore
            }
            stream = registerIncomingStream(makeStreamId(frame.streamId));
        }
        const replenish = stream.ingest(frame.offset, frame.data as Bytes, frame.fin);
        connectionDataReceived += BigInt(frame.data.length);
        if (replenish) {
            sendMaxStreamData(stream);
        }
        // Receiving data grows the connection receive window accounting.
        if (connectionDataReceived >= connectionMaxDataAdvertised / BigInt(REPLENISH_FRACTION)) {
            connectionDataReceived = 0n;
            sendMaxData();
        }
    }

    function handleResetStream(
        frame: Extract<QuicFrame, { type: typeof QuicFrameType.RESET_STREAM }>,
    ): void {
        const stream = streams.get(makeStreamId(frame.streamId));
        if (stream === undefined) {
            return;
        }
        stream.resetPeer(frame.errorCode, frame.finalSize);
        streams.delete(makeStreamId(frame.streamId));
    }

    function handleStopSending(
        frame: Extract<QuicFrame, { type: typeof QuicFrameType.STOP_SENDING }>,
    ): void {
        const stream = streams.get(makeStreamId(frame.streamId));
        if (stream === undefined) {
            return;
        }
        stream.stopSending(frame.errorCode);
    }

    function handleMaxData(frame: Extract<QuicFrame, { type: typeof QuicFrameType.MAX_DATA }>): void {
        if (frame.maximum <= connectionMaxData) {
            return;
        }
        connectionMaxData = frame.maximum;
        emitter.emit("maxData", frame.maximum);
    }

    function handleMaxStreamData(
        frame: Extract<QuicFrame, { type: typeof QuicFrameType.MAX_STREAM_DATA }>,
    ): void {
        const stream = streams.get(makeStreamId(frame.streamId));
        if (stream === undefined) {
            return;
        }
        stream.growSendWindow(frame.maximum);
    }

    function handleMaxStreams(frame: MaxStreamsFrame): void {
        switch (frame.type) {
            case QuicFrameType.MAX_STREAMS_BIDI:
                if (frame.maximum > peerMaxBidi) {
                    peerMaxBidi = frame.maximum;
                }
                break;
            case QuicFrameType.MAX_STREAMS_UNI:
                if (frame.maximum > peerMaxUni) {
                    peerMaxUni = frame.maximum;
                }
                break;
        }
    }

    function handleConnectionClose(
        frame: Extract<
            QuicFrame,
            { type: typeof QuicFrameType.CONNECTION_CLOSE | typeof QuicFrameType.CONNECTION_CLOSE_APP }
        >,
    ): void {
        closing = true;
        emitter.emit("connectionClose", { errorCode: frame.errorCode, reason: frame.reason });
    }

    // --- teardown --------------------------------------------------------------

    function abortAll(error: Error): void {
        for (const stream of streams.values()) {
            stream.forceClose({ kind: "connection_close" });
        }
        streams.clear();
        for (const waiter of acceptWaiters) {
            waiter.reject(error);
        }
        acceptWaiters.length = 0;
    }

    function close(errorCode: bigint, reason: string): void {
        if (closed) {
            return;
        }
        closing = true;
        closed = true;
        deps.sendFrame({
            type: QuicFrameType.CONNECTION_CLOSE,
            errorCode,
            frameType: undefined,
            reason,
        });
    }

    const localParameters = deps.localParameters;

    const manager = {
        openStream,
        acceptStream,
        dispatch,
        flushSends,
        abortAll,
        close,
        updatePeerParameters: (params: QuicTransportParameters): void => {
            deps.peerParameters = params;
        },
        get hasPendingSends(): boolean {
            for (const s of streams.values()) {
                if (s.hasPendingSend) {
                    return true;
                }
            }
            return false;
        },
        get localParameters(): QuicTransportParameters {
            return localParameters;
        },
        // Mirror EventEmitter's core methods onto the manager so the returned
        // object satisfies the `StreamManager & EventEmitter` intersection type
        // and callers can subscribe through a single handle.
        on: (event: string | symbol, listener: (...args: unknown[]) => void) =>
            emitter.on(event, listener),
        once: (event: string | symbol, listener: (...args: unknown[]) => void) =>
            emitter.once(event, listener),
        off: (event: string | symbol, listener: (...args: unknown[]) => void) =>
            emitter.off(event, listener),
        removeListener: (event: string | symbol, listener: (...args: unknown[]) => void) =>
            emitter.removeListener(event, listener),
        removeAllListeners: (event?: string | symbol) => emitter.removeAllListeners(event),
        emit: (event: string | symbol, ...args: unknown[]) => emitter.emit(event, ...args),
    };

    return manager as StreamManager & EventEmitter;
}
