import { defineConfig } from "vite";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import pkg from "./package.json" with { type: "json" };

const buildCount = execSync("git rev-list HEAD --count").toString().trim();

export default defineConfig(({ mode }) => {
  const isDev = mode === "development";
  return {
    root: "src",
    base: "./",
    resolve: {
      // node-jose treats any non-empty `crypto` module as Node's crypto. Vite's
      // default browser stub for Node built-ins is non-empty, so force an empty
      // one; node-jose then falls back to WebCrypto.
      alias: {
        crypto: fileURLToPath(new URL("./empty-module.cjs", import.meta.url)),
      },
    },
    define: {
      BUILD_VERSION: JSON.stringify(`${pkg.version}.${buildCount}`),
      global: "globalThis",
    },
    css: {
      preprocessorOptions: {
        scss: { quietDeps: true },
      },
    },
    build: {
      outDir: "../dist",
      emptyOutDir: true,
      sourcemap: isDev,
      minify: !isDev,
      chunkSizeWarningLimit: 1024,
      rollupOptions: {
        output: {
          // Stable, unhashed names so propagate.sh and the github.io layout
          // (jwt/js/main.js, jwt/css/main.css) keep working.
          entryFileNames: "js/main.js",
          assetFileNames: (assetInfo) =>
            assetInfo.names?.some((n) => n.endsWith(".css"))
              ? "css/main.css"
              : "assets/[name]-[hash][extname]",
        },
      },
    },
  };
});
