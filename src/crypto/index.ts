/**
 * QUIC key derivation (RFC 9001 §5).
 *
 * Barrel re-export so the QUIC package's consumers can import key-derivation
 * helpers from a single path.
 */

export {
    quicHkdfExpandLabel,
    deriveQuicSecrets,
    deriveInitialSecrets,
    INITIAL_SALT_V1,
    QUIC_IV_LENGTH,
    type QuicProtectionSecrets,
    type InitialSecrets,
} from "./key-derivation.js";
