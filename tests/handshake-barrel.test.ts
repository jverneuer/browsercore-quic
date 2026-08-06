/**
 * Barrel coverage test for the QUIC TLS handshake module (src/handshake/index.ts).
 *
 * The handshake barrel re-exports the TLS handshake runner, the QUIC↔TLS
 * transport adapter, and the phase/result types. Importing it through `*` and
 * asserting that each export is present and of the right kind exercises the
 * barrel module itself (its export statements are statements that coverage
 * counts) and catches any accidental removal or rename.
 *
 * Targets: src/handshake/index.ts (currently 0% coverage).
 */

import { describe, it, expect } from "vitest";
import * as handshake from "../src/handshake/index.js";

describe("handshake barrel (index.ts)", () => {
    it("re-exports runQuicHandshake as a function", () => {
        expect(typeof handshake.runQuicHandshake).toBe("function");
    });

    it("re-exports adaptQuicStreamToTransport as a function", () => {
        expect(typeof handshake.adaptQuicStreamToTransport).toBe("function");
    });

    it("re-exports QuicTransportAdapter as a class-constructable value", () => {
        expect(handshake.QuicTransportAdapter).toBeDefined();
        // A class is a function under the hood (its constructor).
        expect(typeof handshake.QuicTransportAdapter).toBe("function");
    });

    it("does not lose any of the runtime exports", () => {
        // QuicKeyPhase, QuicPhaseSecrets, and QuicHandshakeResult are type-only
        // exports (export type) — TypeScript erases them at compile time, so
        // they are not present at runtime. We verify only the value exports
        // via static property access (a computed lookup trips oxlint).
        expect(handshake.runQuicHandshake).toBeDefined();
        expect(handshake.adaptQuicStreamToTransport).toBeDefined();
        expect(handshake.QuicTransportAdapter).toBeDefined();
    });
});
