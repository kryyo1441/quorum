// A complete guarded updater in ~40 lines: the pattern for ANY app (desktop, CLI, agent runtime, MCP server).
// Wrap, don't replace: keep your existing update server and installer; add one gate between "downloaded" and "install".
import { copyFileSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseTrust, verifyUpdate, type Verdict } from "@uw/client-sdk";
import type { ReleaseEntry } from "@uw/shared";

export type Installed = { app: string; platform: string; version: string };

/** Returns the verdict; installs ONLY on ok. `install` is whatever your app already does with a downloaded file. */
export async function guardedUpdate(o: { updateUrl: string; trust: unknown; current: Installed; install: (file: string) => void; fetch?: typeof fetch; now?: () => number }): Promise<Verdict> {
  const f = o.fetch ?? fetch;
  // 1. ask your normal update server, exactly as before
  const manifest = (await (await f(`${o.updateUrl}/latest/${o.current.app}/${o.current.platform}`)).json()) as ReleaseEntry;
  const bytes = new Uint8Array(await (await f(manifest.url)).arrayBuffer());
  // 2. the gate. `trust` is baked into the app at build time; `expected` pins app, platform and blocks downgrades.
  const cfg = parseTrust(o.trust, { expected: { app: o.current.app, platform: o.current.platform, installedVersion: o.current.version } });
  const verdict = await verifyUpdate(bytes, manifest, cfg, { fetch: f, now: o.now ?? Date.now });
  if (!verdict.ok) return verdict; // fail closed: log down, witness down, tampered, downgraded, unlogged... all land here
  // 3. only now touch the disk
  const file = join(mkdtempSync(join(tmpdir(), "update-")), "update.bin");
  writeFileSync(file, bytes);
  o.install(file);
  return verdict;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [trustPath, updateUrl, app, platform, version] = process.argv.slice(2);
  if (!trustPath || !updateUrl) { console.error("usage: tsx updater.ts <trust.json> <update-server-url> <app> <platform> <installed-version>"); process.exit(2); }
  const v = await guardedUpdate({ updateUrl, trust: JSON.parse(readFileSync(trustPath, "utf8")), current: { app, platform, version }, install: (file) => { copyFileSync(file, "./installed.bin"); console.log("installed ./installed.bin"); } });
  console.log(v.ok ? `OK: installed ${v.entry.version}` : `BLOCKED ${v.reason}: ${v.detail}`);
  process.exit(v.ok ? 0 : 1);
}
