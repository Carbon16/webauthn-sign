import { defineConfig } from "tsup";

export default defineConfig([
  // Server entry (Node.js, no DOM types needed)
  {
    entry: {
      index: "src/index.ts",
      server: "src/server.ts",
    },
    format: ["esm", "cjs"],
    dts: true,
    splitting: true,
    treeshake: true,
    sourcemap: true,
    clean: true,
    platform: "node",
    target: "node18",
  },
  // Client entry (browser, no Node built-ins)
  {
    entry: {
      client: "src/client.ts",
    },
    format: ["esm", "cjs"],
    dts: true,
    splitting: false,
    treeshake: true,
    sourcemap: true,
    platform: "browser",
    target: "es2020",
  },
]);
