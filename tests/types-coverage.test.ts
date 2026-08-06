/**
 * Coverage tests for the Logger implementations (types.ts lines 440-456).
 *
 * Exercises silentLogger (the no-op default) and devLogger (the console-delegating
 * development logger). The devLogger's three method bodies each call through to
 * the global console — those are the uncovered lines on 450-456.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { silentLogger, devLogger } from "../src/types.js";

describe("silentLogger", () => {
    it("is a no-op for debug, warn, and error", () => {
        // Should not throw regardless of arguments.
        expect(() => {
            silentLogger.debug("ignored", { extra: true });
            silentLogger.warn("ignored", 42);
            silentLogger.error("ignored", new Error("nope"));
        }).not.toThrow();
    });

    it("returns void from every method", () => {
        expect(silentLogger.debug("x")).toBeUndefined();
        expect(silentLogger.warn("x")).toBeUndefined();
        expect(silentLogger.error("x")).toBeUndefined();
    });
});

describe("devLogger", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it("delegates debug to console.debug", () => {
        const spy = vi.spyOn(console, "debug").mockImplementation(() => {});
        devLogger.debug("msg", { extra: true });
        expect(spy).toHaveBeenCalledWith("msg", { extra: true });
    });

    it("delegates warn to console.warn", () => {
        const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
        devLogger.warn("msg", 42);
        expect(spy).toHaveBeenCalledWith("msg", 42);
    });

    it("delegates error to console.error", () => {
        const spy = vi.spyOn(console, "error").mockImplementation(() => {});
        const err = new Error("boom");
        devLogger.error("msg", err);
        expect(spy).toHaveBeenCalledWith("msg", err);
    });

    it("forwards a rest-parameter list of arbitrary length", () => {
        const spy = vi.spyOn(console, "debug").mockImplementation(() => {});
        devLogger.debug("a", "b", "c", "d");
        expect(spy).toHaveBeenCalledWith("a", "b", "c", "d");
    });
});
