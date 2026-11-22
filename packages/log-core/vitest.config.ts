import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";
// Tests run against workspace SOURCE, not stale dist builds.
const p = (r: string) => fileURLToPath(new URL(r, import.meta.url));
export default defineConfig({ resolve: { alias: {
  "@uw/shared": p("../shared/src/index.ts"),
} } });
