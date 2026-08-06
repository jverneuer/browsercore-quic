/**
 * Coverage tests for the hash-length helper (crypto/hash-length.ts).
 *
 * Exercises hashLengthFor() across every HashId variant. The default branch
 * (lines 18-20) calls assertNever — it is unreachable at compile time for a
 * well-typed HashId, so reaching it in a test requires bypassing the type
 * system to feed an invalid value. That branch is the exhaustiveness guard that
 * fires if a new HashId member is ever added without a matching case.
 */

import { describe, it, expect } from "vitest";
import { hashLengthFor } from "../src/crypto/hash-length.js";
import { SHA_256, SHA_384 } from "@browsercore/crypto";

describe("hashLengthFor", () => {
    it("returns 32 bytes for SHA-256", () => {
        expect(hashLengthFor(SHA_256)).toBe(32);
        // Also verify via the branded literal form.
        expect(hashLengthFor("SHA-256" as typeof SHA_256)).toBe(32);
    });

    it("returns 48 bytes for SHA-384", () => {
        expect(hashLengthFor(SHA_384)).toBe(48);
        expect(hashLengthFor("SHA-384" as typeof SHA_384)).toBe(48);
    });

    it("throws via assertNever for any non-hash value (the default branch)", () => {
        // The default branch is unreachable for a well-typed HashId. To cover
        // it we must feed a value that is not SHA-256 or SHA-384 — a forced
        // cast is the standard way to exercise an exhaustiveness guard.
        const notAHash = "SHA-512" as unknown as Parameters<typeof hashLengthFor>[0];
        expect(() => hashLengthFor(notAHash)).toThrow(/Unexpected value/);
    });
});
