/**
 * QUIC TLS handshake (RFC 9001 §4, §8).
 *
 * Barrel re-export so consumers can import the handshake orchestration and the
 * QUIC→TLS transport adapter from a single path.
 */

export { runQuicHandshake } from "./quic-handshake.js";
export type {
    QuicKeyPhase,
    QuicPhaseSecrets,
    QuicHandshakeResult,
} from "./quic-handshake.js";

export { adaptQuicStreamToTransport, QuicTransportAdapter } from "./quic-transport-adapter.js";
