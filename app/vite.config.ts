import { defineConfig } from "vite";

// Fixed port (strict): `tauri dev` loads http://localhost:1420; a busy port
// is an error, never a second server on another port.
export default defineConfig({
  clearScreen: false,
  server: { port: 1420, strictPort: true, host: "localhost" },
  build: {
    target: "safari16",
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
});
