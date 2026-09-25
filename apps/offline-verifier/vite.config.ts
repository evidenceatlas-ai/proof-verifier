import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { defineConfig } from "vite";

export default defineConfig({
  plugins: [
    {
      name: "offline-verifier-index",
      generateBundle() {
        this.emitFile({
          type: "asset",
          fileName: "index.html",
          source: readFileSync(resolve(import.meta.dirname, "index.html"), "utf8"),
        });
      },
    },
  ],
  build: {
    copyPublicDir: false,
    emptyOutDir: true,
    lib: {
      entry: resolve(import.meta.dirname, "src/main.ts"),
      name: "ReviewedProofOfflineVerifier",
      formats: ["iife"],
      fileName: () => "assets/verifier.js",
      cssFileName: "assets/verifier",
    },
    outDir: "dist",
    sourcemap: false,
    target: "es2022",
  },
});
