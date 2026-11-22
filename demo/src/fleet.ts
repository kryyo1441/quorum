import { createHash, createHmac } from "node:crypto";
import { signEntry } from "@uw/log-core";
import type { Observation, ReleaseEntry } from "@uw/shared";

export type Fetch = typeof fetch;
export type Env = { updateUrl: string; witnessUrls: string[]; logUrl?: string; vendor: { keyId: string; secretKey: string }; fetch: Fetch };
export type ClientResult = { id: string; state: "verified" | "blocked"; reason?: "HASH_MISMATCH"; sha256: string };

export const sha256 = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
export const clientIds = (n: number) => Array.from({ length: n }, (_, i) => `c${i + 1}`);

export const GOOD = new TextEncoder().encode("notepad-minus 2.1.0 genuine build");
export const EVIL = new TextEncoder().encode("notepad-minus 2.1.0 TAMPERED build");
export const APP = "notepad-minus", VERSION = "2.1.0", PLATFORM = "win-x64";

/** The vendor CLI step: build the entry, sign it with the vendor release key, publish to the update server and (when logUrl is set) the log. */
export async function seed(e: Env) {
  const entry: ReleaseEntry = signEntry({ app: APP, version: VERSION, platform: PLATFORM, sha256: sha256(GOOD), size: GOOD.length,
    url: `${e.updateUrl}/download/${APP}/${VERSION}/${PLATFORM}`, publishedAt: new Date().toISOString(), vendorKeyId: e.vendor.keyId }, e.vendor.secretKey);
  await e.fetch(`${e.updateUrl}/admin/release`, { method: "POST", body: JSON.stringify({ entry, binary: Buffer.from(GOOD).toString("base64") }) });
  if (e.logUrl) {
    const r = await e.fetch(`${e.logUrl}/entries`, { method: "POST", body: JSON.stringify(entry) });
    if (!r.ok) throw new Error(`log rejected the release: ${r.status} ${await r.text()}`);
  }
  return entry;
}
export const attack1 = (e: Env, clientId: string) =>
  e.fetch(`${e.updateUrl}/admin/target`, { method: "POST", body: JSON.stringify({ clientId, binary: Buffer.from(EVIL).toString("base64") }) });
export const reset = (e: Env) => e.fetch(`${e.updateUrl}/admin/reset`, { method: "POST" });

/** One client: fetch manifest + binary, hash it, compare (check 1 of §7.2 only), report what it saw to every witness. */
export async function runClient(e: Env, id: string): Promise<ClientResult> {
  const manifest = (await (await e.fetch(`${e.updateUrl}/latest/${APP}/${PLATFORM}`)).json()) as ReleaseEntry;
  const bin = new Uint8Array(await (await e.fetch(`${manifest.url}?client=${id}`)).arrayBuffer());
  const seen = sha256(bin);
  const obs: Observation = { app: manifest.app, version: manifest.version, platform: manifest.platform, sha256: seen, sthRoot: "", sthSize: 0,
    clientPseudonym: createHmac("sha256", `secret-${id}`).update(manifest.app).digest("hex"), observedAt: new Date().toISOString() };
  await Promise.all(e.witnessUrls.map((w) => e.fetch(`${w}/observations`, { method: "POST", body: JSON.stringify(obs) })));
  return seen === manifest.sha256 ? { id, state: "verified", sha256: seen } : { id, state: "blocked", reason: "HASH_MISMATCH", sha256: seen };
}
export const runFleet = (e: Env, n = 12) => Promise.all(clientIds(n).map((id) => runClient(e, id)));
