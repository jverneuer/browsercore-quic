/**
 * Hash-length helper for QUIC key derivation.
 *
 * Maps a branded HashId to its digest length in bytes. Mirrors the same helper
 * in @browsercore/tls so QUIC's key derivation can size the initial traffic
 * secrets (which are Hash.length bytes, RFC 9001 §5.2).
 */

import { assertNever } from "../utils.js";
import type { HashId } from "@browsercore/crypto";

/** Output length (bytes) of a hash algorithm. */
export function hashLengthFor(hash: HashId): number {
    switch (hash) {
        case "SHA-256":
            return 32;
        case "SHA-384":
            return 48;
        default:
            return assertNever(hash);
    }
}
