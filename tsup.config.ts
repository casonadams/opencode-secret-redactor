import { defineConfig } from "tsup"

export default defineConfig({
  entry: ["src/index.ts", "src/plugin.ts", "src/tui.ts", "src/rpc.ts"],
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
})
