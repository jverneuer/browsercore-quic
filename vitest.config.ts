import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        name: "quic",
        root: ".",
        include: ["tests/**/*.test.ts"],
        environment: "node",
        globals: false,
        testTimeout: 30_000,
        hookTimeout: 30_000,
        coverage: {
            provider: "v8",
            include: ["src/**/*.ts"],
            // Barrel files (index.ts) contain only `export { } from` re-exports
            // that v8 cannot instrument — they have zero executable statements.
            exclude: ["src/**/index.ts"],
            all: true,
            reporter: ["text", "html", "json-summary"],
            thresholds: { statements: 94, branches: 94, functions: 94, lines: 94 },
        },
    },
});
