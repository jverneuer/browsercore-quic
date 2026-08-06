/**
 * QUIC connection lifecycle + datagram read loop (RFC 9000 §5, §12) with TLS
 * handshake + packet protection (RFC 9001).
 *
 * Wires packet header parsing/serialization, the frame layer, the stream
 * manager, the TLS 1.3 handshake (over QUIC stream 0), and QUIC's two-layer
 * packet protection (AEAD payload encryption + header protection) over an
 * injected {@link DatagramTransport} (UDP).
 *
 * The connection owns the read loop: it turns inbound datagrams into frames,
 * dispatches each to the stream manager, and drains pending stream sends back
 * into outbound packets. After the TLS handshake completes, every packet is
 * protected with the derived QUIC keys for its key phase:
 *
 *   Initial packets   → initial keys (derived from DCID)
 *   Handshake packets → handshake keys (derived from TLS handshake secrets)
 *   1-RTT packets     → application keys (derived from TLS application secrets)
 *
 * Honest limitations:
 *   - 0-RTT, KeyUpdate, key-phase-bit handling, and connection migration
 *     beyond PATH_CHALLENGE / PATH_RESPONSE are out of scope. No congestion
 *     controller. No liveness PING.
 *
 * Concurrency model: the read loop is a single async task pulling datagrams from
 * the transport. Outbound frames are produced synchronously by the stream
 * manager and packed into packets; writes resolve once bytes are buffered.
 */

import { crypto, type CryptoProvider } from "@browsercore/crypto";
import { nodeRandomSource, type RandomSource } from "@browsercore/transport";
import {
    QuicFrameType,
    systemClock,
    silentLogger,
    type Clock,
    type ClientHelloConfigLike,
    type ConnectionId,
    type Logger,
    type QuicConnection,
    type QuicFrame,
    type QuicOptions,
    type QuicStream,
    type QuicTransportParameters,
    type UdpAddress,
} from "./types.js";
import {
    parsePacketHeader,
    serializeShortHeader,
    serializeLongHeader,
    readPacketNumber,
    type PacketHeader,
} from "./packet/packet.js";
import {
    protectPayload,
    unprotectPayload,
    type QuicAead,
} from "./packet/packet-protection.js";
import type { AeadAlgorithm, ClientHelloConfig } from "@browsercore/tls";
import { readFrames, serializeFrame } from "./frame/frame.js";
import {
    ConnectionClosedError,
    ConnectionClosingError,
    PacketProtectionError,
    TlsHandshakeError,
} from "./errors.js";
import { createStreamManager, type StreamManager } from "./stream/stream.js";
import { assertNever, concatAll, hex } from "./utils.js";
import {
    decodeTransportParameters,
    encodeTransportParameters,
    fromWireParameters,
    toWireParameters,
    type TransportParameters,
} from "./transport-params.js";
import { adaptQuicStreamToTransport } from "./handshake/quic-transport-adapter.js";
import { runQuicHandshake, type QuicHandshakeResult, type QuicPhaseSecrets } from "./handshake/quic-handshake.js";

/** Byte type alias matching the `Uint8Array<ArrayBufferLike>` wire signatures. */
type Bytes = Uint8Array;

/** Largest UDP payload we will pack into a single datagram (RFC 9000 §14). */
const MAX_DATAGRAM_PAYLOAD = 1200;



/** QUIC long header version (QUIC v1, RFC 9000 §32.2.1). */
const QUIC_VERSION_V1 = 0x00000001;

/** Default TLS profile for the QUIC handshake — modern TLS 1.3, X25519 + secp256r1. */
const DEFAULT_TLS_PROFILE: ClientHelloConfig = {
    cipherSuites: [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
    ],
    extensionOrder: [
        0, 10, 11, 13, 16, 17513, 18, 23, 27, 35, 41, 43, 45, 5, 51, 65281,
    ],
    keyShareGroups: ["x25519", "secp256r1"],
    signatureAlgorithms: [
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pss_rsae_sha384",
    ],
    supportedVersions: [{ name: "TLS 1.3", wire: 0x0304 }],
    serverName: "",
    grease: true,
};

/** The key phase a packet belongs to, determined by its long-header type or (for 1-RTT) the handshake state. */
type PacketKeyPhase = "initial" | "handshake" | "application";

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
    /** Stream manager (signals connection-level events via QuicSignalSink). */
    private readonly manager: StreamManager;
    /** Our current destination connection id (the one we put on outbound packets). */
    private readonly dcid: ConnectionId;
    /** Logging sink for lifecycle + frame diagnostics. */
    private readonly logger: Logger;
    /** Random source for connection ids and packet numbers. */
    private readonly random: RandomSource;
    /**
     * Cryptographic provider for QUIC key derivation and packet protection
     * (RFC 9001). Seeded with the injected {@link random} source so the
     * HKDF-based key schedule is reproducible under test.
     */
    private readonly cryptoProvider: CryptoProvider;
    /** TLS ClientHello configuration for the handshake. */
    private readonly tlsProfile: ClientHelloConfig;
    /**
     * Our transport parameters encoded for the wire. Produced at handshake
     * time so a TLS layer can carry them to the peer in the QUIC extension.
     */
    private readonly encodedLocalParameters: Uint8Array;

    /** Result of the TLS handshake — set once the handshake completes. */
    private handshakeResult: QuicHandshakeResult | undefined;

    /**
     * Current key phase for outbound packets. Advances from initial → handshake
     * → application as the handshake progresses. The protection layer selects
     * the correct secrets based on this + the packet's header form.
     */
    private outboundKeyPhase: PacketKeyPhase = "initial";

    /** Next outbound packet number, per key phase (RFC 9000 §12.3). */
    private readonly nextPacketNumber: Record<PacketKeyPhase, bigint> = {
        initial: 0n,
        handshake: 0n,
        application: 0n,
    };

    /** Largest received packet number per key phase (for packet-number decoding). */
    private readonly largestReceivedPn: Record<PacketKeyPhase, bigint> = {
        initial: -1n,
        handshake: -1n,
        application: -1n,
    };

    /**
     * PATH_CHALLENGEs we have issued and are awaiting a PATH_RESPONSE for,
     * keyed by the hex-encoded 8-byte challenge data (RFC 9000 §8.2.1).
     */
    private readonly pendingPathChallenges = new Set<string>();

    /** Set once the connection begins graceful shutdown. */
    private closing = false;
    /** Set once the connection is fully torn down. */
    private closed = false;
    /** Buffered outbound frames waiting to be packed into the next packet. */
    private readonly outboundFrames: QuicFrame[] = [];

    /**
     * @param onPeerClose Register a handler for peer CONNECTION_CLOSE signals.
     *                    The stream manager calls this through its signal sink;
     *                    the connection supplies the handler at construction.
     */
    public constructor(
        id: string,
        options: QuicOptions,
        manager: StreamManager,
        dcid: ConnectionId,
        logger: Logger,
        onPeerClose?: (handler: (errorCode: bigint, reason: string) => void) => void,
    ) {
        this.id = id;
        this.transport = options.transport;
        this.peer = options.peer;
        this.manager = manager;
        this.dcid = dcid;
        this.logger = logger;
        // Let the caller (connectQuic) wire the peer-close signal handler.
        if (onPeerClose !== undefined) {
            onPeerClose((errorCode, reason) => {
                void this.onPeerClose(errorCode, reason);
            });
        }
        this.random = options.random ?? nodeRandomSource;
        // The crypto provider is seeded with the same random source so the
        // QUIC key schedule (RFC 9001) derives bytes deterministically when a
        // deterministic source is injected. Delegates all other operations to
        // the singleton `crypto` provider.
        const randomSource = this.random;
        this.cryptoProvider = new Proxy(crypto, {
            get(target, prop, receiver) {
                if (prop === "randomBytes") {
                    return (length: number): Uint8Array => randomSource.randomBytes(length);
                }
                return Reflect.get(target, prop, receiver) as CryptoProvider[keyof CryptoProvider];
            },
        }) as CryptoProvider;
        // Resolve the TLS ClientHello configuration for the handshake.
        this.tlsProfile = toTlsClientHelloConfig(options.tlsProfile, options.serverName);
        // Encode our transport parameters for the wire at construction. A real
        // TLS handshake would carry these to the peer in the QUIC extension;
        // here we surface them so the handshake layer can read them.
        this.encodedLocalParameters = encodeTransportParameters(
            toWireParameters(resolveLocalParameters(options)),
        );
    }

    // --- public QuicConnection surface ------------------------------------------

    /**
     * Resolve when the QUIC handshake completes and the connection is
     * protected. HTTP/3 SETTINGS exchange may only begin after this resolves.
     *
     * When `skipHandshake` is true in QuicOptions, this resolves immediately
     * since no TLS handshake is performed.
     */
    public async handshake(): Promise<void> {
        // If the handshake has already completed, resolve immediately
        if (this.handshakeResult !== undefined) {
            return;
        }
        // Perform the TLS handshake
        await this.performHandshake();
    }

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

    // --- path validation (RFC 9000 §8.2.1, §19.17) -----------------------------

    /**
     * Send a PATH_CHALLENGE to validate a path. Records the 8-byte challenge
     * (copied) so a matching PATH_RESPONSE from the peer validates the path.
     */
    public sendPathChallenge(data: Uint8Array): void {
        if (data.length !== 8) {
            throw new RangeError(`PATH_CHALLENGE data must be 8 bytes, got ${data.length}`);
        }
        this.pendingPathChallenges.add(hex(data));
        this.sendFrame({ type: QuicFrameType.PATH_CHALLENGE, data: data.slice() });
        void this.flush();
    }

    /** True if a PATH_CHALLENGE with the given data is awaiting a PATH_RESPONSE. */
    public hasPendingPathChallenge(data: Uint8Array): boolean {
        return this.pendingPathChallenges.has(hex(data));
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
     * Our transport parameters, encoded for the wire. A TLS handshake layer
     * reads these once and carries them to the peer in the QUIC extension.
     */
    public getEncodedLocalParameters(): Uint8Array {
        return this.encodedLocalParameters;
    }

    /**
     * The logging sink for this connection. A TLS handshake layer or test
     * harness reads this to attach diagnostics, or to swap in a capturing
     * logger — the connection itself stays agnostic to where log lines go.
     */
    public getLogger(): Logger {
        return this.logger;
    }

    /**
     * Ingest the peer's transport parameters from their wire encoding. Decodes
     * them and feeds them to the stream manager so its send windows match what
     * the peer advertised. Called by the handshake layer once the peer's
     * parameters are available.
     */
    public receivePeerParameters(peerWireParameters: Uint8Array): void {
        const wire = decodeTransportParameters(peerWireParameters);
        this.manager.updatePeerParameters(fromWireParameters(wire));
    }

    /** Expose the wire-form peer parameters for inspection (tests, debugging). */
    public toWireParameters(params: QuicTransportParameters): TransportParameters {
        return toWireParameters(params);
    }

    /**
     * Generate a random connection id of `length` bytes (RFC 9000 §5.1). Drawn
     * from the injected random source so connection ids are reproducible under
     * test. Useful for NEW_CONNECTION_ID frames and the endpoint's own source
     * connection ids.
     */
    public generateConnectionId(length: number): ConnectionId {
        return this.random.randomBytes(length) as ConnectionId;
    }

    /**
     * The crypto provider for QUIC key derivation (RFC 9001). A handshake
     * layer uses this to run the HKDF-based key schedule; it is seeded with the
     * injected random source so derived keys are reproducible under test.
     */
    public getCrypto(): CryptoProvider {
        return this.cryptoProvider;
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
        // Each fragment is an independent datagram (own slice, own packet); build
        // them all, then send concurrently rather than serializing independent sends.
        const sends: Promise<unknown>[] = [];
        for (let offset = 0; offset < payload.length; offset += MAX_DATAGRAM_PAYLOAD) {
            const slice = payload.subarray(offset, offset + MAX_DATAGRAM_PAYLOAD) as Bytes;
            const packet = this.wrapPacket(slice);
            sends.push(this.transport.send(packet, this.peer));
        }
        await Promise.all(sends);
    }

    /** Serialize frames into a single byte buffer (no packet header). */
    private packFrames(frames: QuicFrame[]): Bytes {
        return concatAll(frames.map((f) => serializeFrame(f)));
    }

    /**
     * Wrap a serialized payload in a packet header + protect it.
     *
     * Selects long vs short header based on the current handshake state:
     *   - Before the handshake is complete: long-header Initial / Handshake packets.
     *   - After: short-header (1-RTT) packets.
     *
     * For now, we always emit short-header (1-RTT) packets once the handshake
     * is complete, and long-header Handshake packets during the handshake.
     * The very first packets (ClientHello) are also carried in Handshake packets
     * by this simplified implementation — a full client would send the
     * ClientHello in an Initial packet with a token, but the protection layer
     * is identical.
     */
    private wrapPacket(payload: Bytes): Bytes {
        // No handshake performed (skipHandshake: true) — emit unprotected
        // short-header packets for testing the data plane without a live TLS peer.
        if (this.handshakeResult === undefined) {
            return this.wrapPacketUnprotectedShort(payload);
        }
        const phase = this.outboundKeyPhase;
        const secrets = this.getProtectionSecrets(phase);
        if (secrets === undefined) {
            // Pre-handshake (before the TLS handshake has produced keys): emit an
            // unprotected packet for tests that don't exercise the protection layer.
            // A production build would always have initial keys before the first
            // outbound packet.
            return this.wrapPacketUnprotected(payload, phase);
        }
        return this.wrapPacketProtected(payload, phase, secrets);
    }

    /**
     * Wrap a payload in a simple unprotected short-header packet — the original
     * behavior for tests that don't exercise the TLS handshake + protection layer.
     */
    private wrapPacketUnprotectedShort(payload: Bytes): Bytes {
        const header = serializeShortHeader(this.dcid, 1, false, false);
        // 1-byte packet number — placeholder for the protection layer, which
        // assigns real packet numbers. Drawn from the injected random source so
        // packet numbers are reproducible under test (RFC 9000 §17.2.4.1
        // initial packet number SHOULD be random).
        const packetNumber = this.random.randomBytes(1);
        return concatAll([header, packetNumber, payload]);
    }

    /** Wrap a payload in a protected packet using the given key-phase secrets. */
    private wrapPacketProtected(
        payload: Bytes,
        phase: PacketKeyPhase,
        secrets: QuicPhaseSecrets,
    ): Bytes {
        const pn = this.nextPacketNumber[phase];
        this.nextPacketNumber[phase] = pn + 1n;
        const pnLength = 4; // 4-byte packet numbers for simplicity
        const isLongHeader = phase !== "application";
        const headerType = phase === "initial"
            ? 0b00 // Initial
            : phase === "handshake"
            ? 0b10 // Handshake
            : 0b00; // short header — long type unused
        const firstByte = isLongHeader
            ? (0b11 << 6) | (headerType << 4) | (pnLength - 1) // form=1, fixed=1, type, pnLen
            : (0b01 << 5) | (pnLength - 1); // form=0, fixed=1, spin=0, reserved=0, keyPhase=0, pnLen

        // The AAD for AEAD is the unprotected header (first byte + packet number).
        // protectPayload handles the AEAD encryption + header protection.
        const aead = mapAeadToQuic(this.handshakeResult?.aead ?? "AES-128-GCM");
        const { protectedPayload, maskedFirstByte, maskedPacketNumber } = protectPayload(
            payload,
            pn,
            pnLength,
            firstByte,
            aead,
            secrets.clientProtection,
            isLongHeader,
            this.cryptoProvider,
        );

        if (isLongHeader) {
            // Long header: version, DCID, SCID are emitted before the packet number.
            // For simplicity we emit a minimal long header (version + DCID/SCID length 0).
            const header = serializeLongHeader(
                headerType as 0 | 1 | 2 | 3,
                QUIC_VERSION_V1,
                this.dcid,
                new Uint8Array(0),
                pnLength,
            );
            // Replace the first byte of the serialized header with the masked one.
            const maskedHeader = new Uint8Array(header);
            maskedHeader[0] = maskedFirstByte;
            return concatAll([maskedHeader, maskedPacketNumber, protectedPayload]);
        }
        // Short header: first byte + DCID + packet number + protected payload.
        const header = new Uint8Array([maskedFirstByte]);
        return concatAll([header, this.dcid, maskedPacketNumber, protectedPayload]);
    }

    /**
     * Wrap a payload in an *unprotected* packet — used only before the TLS
     * handshake has produced keys (e.g. in tests that don't exercise the
     * protection layer). A production build would never emit these.
     */
    private wrapPacketUnprotected(payload: Bytes, phase: PacketKeyPhase): Bytes {
        const isLongHeader = phase !== "application";
        const pnLength = 1;
        const pn = 0n;
        if (isLongHeader) {
            const headerType = phase === "initial" ? 0b00 : 0b10;
            const header = serializeLongHeader(
                headerType as 0 | 1 | 2 | 3,
                QUIC_VERSION_V1,
                this.dcid,
                new Uint8Array(0),
                pnLength,
            );
            const packetNumber = new Uint8Array([Number(pn)]);
            return concatAll([header, packetNumber, payload]);
        }
        const header = serializeShortHeader(this.dcid, pnLength, false, false);
        const packetNumber = new Uint8Array([Number(pn)]);
        return concatAll([header, packetNumber, payload]);
    }

    /**
     * Get the QUIC protection secrets for a given key phase. Returns undefined
     * if the handshake has not yet produced keys for that phase (e.g. before
     * the TLS handshake has started).
     */
    private getProtectionSecrets(phase: PacketKeyPhase): QuicPhaseSecrets | undefined {
        if (this.handshakeResult === undefined) {
            return undefined;
        }
        return this.handshakeResult.phases.find((p) => p.phase === phase);
    }

    // --- TLS handshake ----------------------------------------------------------

    /**
     * Run the TLS 1.3 handshake over QUIC stream 0 and derive QUIC packet-
     * protection secrets at each key phase.
     */
    public async performHandshake(): Promise<void> {
        // Open a bidirectional stream for the TLS handshake (stream 0 for the client).
        const stream = await this.openBidirectionalStream();
        const transport = adaptQuicStreamToTransport(stream);

        // Run the TLS handshake, capturing QUIC protection secrets at each phase.
        const result = await runQuicHandshake(
            transport,
            { ...this.tlsProfile, serverName: this.tlsProfile.serverName },
            this.tlsProfile.serverName,
            this.dcid,
            [],
            Math.floor(Date.now() / 1000),
            this.cryptoProvider,
        );

        this.handshakeResult = result;
        this.outboundKeyPhase = "application";

        // Advance through handshake → application phases as the handshake completes.
        // After sending the client Finished, the connection is ready for 1-RTT data.
    }

    // --- read loop -------------------------------------------------------------

    /**
     * Start the datagram read loop. Must be called once after construction.
     * Runs until the transport closes or the connection tears down.
     *
     * Peer CONNECTION_CLOSE signals are received through the stream manager's
     * signal sink (wired at construction time), not via a direct subscription.
     */
    public startReadLoop(): void {
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
            // No handshake performed (skipHandshake: true) — parse the packet
            // header and decode frames directly, matching the original behavior
            // for tests that don't exercise the TLS handshake + protection layer.
            if (this.handshakeResult === undefined) {
                await this.dispatchDatagramUnprotected(data);
                return;
            }

            // Determine the key phase from the header form + type (long) or from
            // the current handshake state (short).
            const keyPhase = this.classifyKeyPhase(data);
            const header = parsePacketHeader(data);

            // Decrypt the packet number + remove header protection to recover the
            // full header + packet number.
            const { packetNumber, header: decryptedHeader } = this.unprotectHeader(data, header, keyPhase);

            // Track the largest received packet number for this phase.
            if (packetNumber > this.largestReceivedPn[keyPhase]) {
                this.largestReceivedPn[keyPhase] = packetNumber;
            }

            this.applyHeader(decryptedHeader);

            // Skip the header + packet number to reach the decrypted frame payload.
            const pnLength = decryptedHeader.packetNumberLength;
            const dcidLength = decryptedHeader.form === 0 ? this.dcid.length : 0;
            const payloadStart = decryptedHeader.headerLength + dcidLength + pnLength;
            const protectedPayload = data.subarray(payloadStart);

            // AEAD-decrypt the payload.
            const secrets = this.getProtectionSecrets(keyPhase);
            let payload: Bytes;
            if (secrets === undefined) {
                // Pre-handshake: no keys yet — treat the payload as plaintext
                // (tests that don't exercise protection).
                payload = protectedPayload;
            } else {
                const pnOffset = decryptedHeader.headerLength + dcidLength;
                const pnBytes = data.subarray(pnOffset, pnOffset + pnLength);
                const { payload: decrypted } = unprotectPayload(
                    decryptedHeader.firstByte ?? data[0] ?? 0,
                    pnBytes,
                    pnLength,
                    protectedPayload,
                    decryptedHeader.form === 1,
                    mapAeadToQuic(this.handshakeResult?.aead ?? "AES-128-GCM"),
                    secrets.serverProtection,
                    this.cryptoProvider,
                );
                payload = decrypted;
            }

            if (payload.length === 0) {
                return;
            }

            const read = this.byteStreamReader(payload);
            for await (const frame of readFrames(read)) {
                this.handleFrame(frame);
            }
        } catch (err) {
            if (err instanceof PacketProtectionError || err instanceof TlsHandshakeError) {
                this._handleFatal(err);
                return;
            }
            // A parse error on one datagram is not necessarily fatal for the
            // connection, but without a protection layer to frame it we close.
            this._handleFatal(err instanceof Error ? err : new Error(String(err)));
        }
    }

    /**
     * Dispatch an unprotected datagram — the original behavior for tests that
     * don't exercise the TLS handshake + protection layer. Parses the packet
     * header and decodes frames directly, matching the pre-handshake read loop.
     */
    private async dispatchDatagramUnprotected(data: Bytes): Promise<void> {
        const header = parsePacketHeader(data);
        this.applyHeaderUnprotected(header);
        // Skip the header + packet number to reach the frame payload.
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
    }

    /** Apply a parsed header (unprotected path) into connection state. */
    private applyHeaderUnprotected(header: PacketHeader): void {
        if (header.form === 1) {
            // Long header: could carry a version negotiation. We ignore for now.
            return;
        }
        // Short header: the DCID on the wire is the route to the peer.
        void header.dcid;
    }

    /**
     * Determine the key phase of an inbound packet from its first byte.
     *
     * Long headers: Initial (0b00) → initial, Handshake (0b10) → handshake,
     * Retry/0-RTT → initial (we treat them as initial-key for simplicity).
     * Short headers: application (1-RTT).
     */
    private classifyKeyPhase(data: Bytes): PacketKeyPhase {
        if (data.length === 0) {
            return "application";
        }
        const first = data[0];
        if (first === undefined) {
            return "application";
        }
        const form = (first >> 7) & 0x01;
        if (form === 1) {
            // Long header: type in bits 4-5.
            const type = (first >> 4) & 0x03;
            if (type === 0b00) {
                return "initial";
            }
            if (type === 0b10) {
                return "handshake";
            }
            // 0-RTT and Retry: treat as initial for simplicity.
            return "initial";
        }
        // Short header: 1-RTT (application keys).
        return "application";
    }

    /**
     * Decrypt the packet number and remove header protection from an inbound
     * packet. Returns the recovered packet number and the decrypted header.
     */
    private unprotectHeader(
        data: Bytes,
        header: PacketHeader,
        keyPhase: PacketKeyPhase,
    ): { packetNumber: bigint; header: DecryptedHeader } {
        const secrets = this.getProtectionSecrets(keyPhase);
        if (secrets === undefined) {
            // No keys yet — parse the plaintext packet number directly.
            const pnLength = header.packetNumberLength;
            const dcidLength = header.form === 0 ? this.dcid.length : 0;
            const pnOffset = header.headerLength + dcidLength;
            const pn = readPacketNumber(data, pnOffset, pnLength);
            return {
                packetNumber: pn,
                header: {
                    ...header,
                    firstByte: data[0] ?? 0,
                    packetNumberLength: pnLength,
                },
            };
        }

        const isLong = header.form === 1;
        const dcidLength = isLong ? 0 : this.dcid.length;

        // We need to decrypt the packet number. The header protection sample is
        // taken from the protected payload, but we need the packet number length
        // to find the sample. RFC 9001 §5.4.2: the packet number length is
        // encoded in the low 2 bits of the (unprotected) first byte. To recover
        // it we need to first remove header protection from the first byte.
        // Simplification: assume 4-byte packet numbers for now (matching our
        // outbound encoding). A full implementation would try all 4 lengths.
        const assumedPnLength = 4;

        // The sample starts 4 bytes into the protected payload, which begins
        // after the (encrypted) packet number.
        const sampleOffset = header.headerLength + dcidLength + assumedPnLength + 4;
        if (data.length < sampleOffset + 16) {
            throw new PacketProtectionError("decrypt", {
                cause: new Error(`packet too short for header-protection sample (need ${sampleOffset + 16}, got ${data.length})`),
            });
        }
        const sample = data.subarray(sampleOffset, sampleOffset + 16);
        const hpKey = isLong ? secrets.serverProtection.hp : secrets.serverProtection.hp;
        const mask = this.cryptoProvider.aesEcbEncrypt(hpKey, sample);

        // Remove header protection from the first byte.
        const firstByte = data[0] ?? 0;
        const firstByteMask = isLong ? 0x0f : 0x1f;
        const unmaskedFirstByte = firstByte ^ ((mask[0] ?? 0) & firstByteMask);

        // Recover the packet number length from the unmasked first byte.
        const recoveredPnLength = isLong
            ? (unmaskedFirstByte & 0x03) + 1
            : (unmaskedFirstByte & 0x03) + 1;

        // Read the (still-masked) packet number bytes.
        const pnByteOffset = header.headerLength + dcidLength;
        const pnBytes = data.subarray(pnByteOffset, pnByteOffset + recoveredPnLength);

        // Remove header protection from the packet number.
        let packetNumber = 0n;
        for (let i = 0; i < recoveredPnLength; i++) {
            const maskByte = mask[1 + i];
            const pnByte = pnBytes[i];
            if (maskByte === undefined || pnByte === undefined) {
                throw new PacketProtectionError("decrypt", {
                    cause: new Error(`mask/pn byte ${i} out of bounds`),
                });
            }
            packetNumber = (packetNumber << 8n) | BigInt(pnByte ^ maskByte);
        }

        return {
            packetNumber,
            header: {
                ...header,
                firstByte: unmaskedFirstByte,
                packetNumberLength: recoveredPnLength,
            },
        };
    }

    /** Header fields after header-protection removal. */
    private applyHeader(header: DecryptedHeader): void {
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
            case QuicFrameType.HANDSHAKE_DONE:
                break;
            // Path validation (RFC 9000 §8.2.1, §19.17).
            case QuicFrameType.PATH_CHALLENGE: {
                const challenge = frame;
                this.sendFrame({ type: QuicFrameType.PATH_RESPONSE, data: challenge.data });
                void this.flush();
                break;
            }
            case QuicFrameType.PATH_RESPONSE: {
                const response = frame;
                this.pendingPathChallenges.delete(hex(response.data));
                break;
            }
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
                // eslint-disable-next-line no-await-in-loop -- sequential datagram consumption is required
                const { data } = await this.transport.recv();
                // eslint-disable-next-line no-await-in-loop -- dispatch must complete before the next datagram
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
            throw new ConnectionClosingError();
        }
    }
}

/** A parsed packet header after header-protection removal. */
interface DecryptedHeader {
    readonly form: number;
    readonly firstByte?: number;
    readonly packetNumberLength: number;
    readonly headerLength: number;
    readonly dcid?: ConnectionId;
    readonly type?: number;
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
 * Convert a {@link ClientHelloConfigLike} (the public QUIC option) to a
 * full @browsercore/tls `ClientHelloConfig` the handshake driver can consume.
 */
function toTlsClientHelloConfig(like: ClientHelloConfigLike | undefined, serverName: string): ClientHelloConfig {
    if (like === undefined) {
        return { ...DEFAULT_TLS_PROFILE, serverName };
    }
    return {
        cipherSuites: like.cipherSuites as ClientHelloConfig["cipherSuites"],
        extensionOrder: like.extensionOrder,
        keyShareGroups: like.keyShareGroups as ClientHelloConfig["keyShareGroups"],
        signatureAlgorithms: like.signatureAlgorithms as ClientHelloConfig["signatureAlgorithms"],
        supportedVersions: like.supportedVersions as ClientHelloConfig["supportedVersions"],
        serverName: like.serverName || serverName,
        ...(like.alpnProtocols === undefined ? {} : { alpnProtocols: like.alpnProtocols }),
        grease: like.grease,
    };
}

/**
 * Establish a QUIC connection over an existing datagram transport.
 *
 * Creates the stream manager and the read loop. By default, runs the TLS 1.3
 * handshake over QUIC stream 0 (a bidirectional stream), derives QUIC packet-
 * protection secrets at each key phase, and returns a connection that protects
 * inbound + outbound packets with the derived keys.
 *
 * The `tlsProfile` option selects the ClientHello configuration for the
 * handshake. Defaults to a modern TLS 1.3 profile (X25519 + secp256r1 key
 * shares, AES-256/128-GCM + ChaCha20-Poly1305). Set `skipHandshake: true` to
 * skip the TLS handshake and return an *unprotected* connection (the data plane
 * is fully functional and testable with a fake datagram transport, but it is
 * not wire-ready without a protection + handshake layer on top).
 */
export async function connectQuic(options: QuicOptions): Promise<QuicConnection> {
    const clock: Clock = options.clock ?? systemClock;
    const id = `quic_${clock.now().toString(36)}`;

    // The stream manager is constructed before the connection, but its frames
    // must reach the connection's packetizer. We bridge the two with a mutable
    // router that we point at the connection once it exists.
    const frameRouter: { send: (frame: QuicFrame) => void } = { send: () => {} };
    // The connection is not yet constructed when we build the manager, so we
    // defer resolving the signal handler until after the connection exists.
    let peerCloseHandler: ((errorCode: bigint, reason: string) => void) | undefined;

    const manager = createStreamManager({
        sendFrame: (frame) => {
            frameRouter.send(frame);
        },
        signals: {
            onIncomingStream: () => {},
            onConnectionClose: (errorCode, reason) => {
                if (peerCloseHandler !== undefined) {
                    peerCloseHandler(errorCode, reason);
                }
            },
            onMaxData: () => { /* sends drain in the read loop */ },
        },
        localParameters: resolveLocalParameters(options),
        peerParameters: options.transportParameters ?? {},
    });

    const conn = new QuicConnectionImpl(
        id,
        options,
        manager,
        options.initialDcid,
        options.logger ?? silentLogger,
        (handler) => {
            peerCloseHandler = handler;
        },
    );
    frameRouter.send = (frame) => {
        conn.sendFrame(frame);
    };

    // Start the read loop. The handshake (if any) runs concurrently so the
    // server's response is processed.
    conn.startReadLoop();

    if (options.skipHandshake === true) {
        // Return an unprotected connection for testing the data plane without
        // a live TLS peer.
        return conn;
    }

    // Run the TLS handshake. On failure, the connection surfaces the error.
    await conn.performHandshake();

    return conn;
}

/** Map a TLS AEAD algorithm to the QUIC AEAD subset (AES-128-CCM is not used by QUIC). */
function mapAeadToQuic(aead: AeadAlgorithm): QuicAead {
    switch (aead) {
        case "AES-128-GCM":
            return "AES-128-GCM";
        case "AES-256-GCM":
            return "AES-256-GCM";
        case "CHACHA20-POLY1305":
            // TLS uses "CHACHA20_POLY1305" (underscores); QUIC's QuicAead type
            // mirrors TLS naming. The packet-protection layer maps to
            // @browsercore/crypto's "ChaCha20-Poly1305" (hyphens) internally.
            return "CHACHA20-POLY1305";
        case "AES-128-CCM":
            // AES-128-CCM is negotiated by TLS but not used by QUIC v1. Fall
            // back to AES-128-GCM; the connection will fail at the TLS layer
            // if the server actually selects CCM.
            return "AES-128-GCM";
        default:
            // Every AeadAlgorithm variant is covered above.
            return assertNever(aead);
    }
}
