import { createHash } from "node:crypto";
import { approveEntry, signEntry } from "@uw/log-core";
import { checkUpdate, reportObservation, verdictOf, type Check, type VerifyConfig } from "@uw/client-sdk";
import type { FailReason, Observation, ReleaseEntry } from "@uw/shared";

export type Fetch = typeof fetch;
export type Env = {
  updateUrl: string; logUrl: string;
  monitor?: { url: string; token: string };           // where the approved-release list lives (§9)
  vendor: { keyId: string; secretKey: string };
  approver?: { secretKey: string };                   // the SECOND key (amendment 13). Whoever publishes honestly holds it; the stolen-key attack deliberately signs without it
  verify: Omit<VerifyConfig, "expected">;             // what every client trusts: log key, witness keys, vendor keys, k
  fetch: Fetch; now?: () => number;
  logFor?: (clientId: string) => string | undefined;   // attack 5: the log THIS client is shown (a malicious operator's fork)
  settle?: () => Promise<void>;                       // in-process worlds: let witnesses/monitor run a cycle (a live stack does this on its own timers)
};
export type ClientResult = {
  id: string; version: string; state: "verified" | "blocked"; reason?: FailReason; detail?: string; sha256: string;
  checks: Check[]; ms: number; hashMs: number; networkMs: number; bytes: number; // §15: latency split into hashing vs network+crypto, and proof+head bytes
};

export const sha256 = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
export const clientIds = (n: number) => Array.from({ length: n }, (_, i) => `c${i + 1}`);
export const GOOD = new TextEncoder().encode("notepad-minus 2.1.0 genuine build");
export const EVIL = new TextEncoder().encode("notepad-minus 2.1.0 TAMPERED build");
export const APP = "notepad-minus", VERSION = "2.1.0", PLATFORM = "win-x64", INSTALLED = "2.0.0";
export const witnessUrls = (e: Env) => e.verify.witnesses.map((w) => w.url);

/** fetch wrapper that counts response bytes (the proof + head overhead of §15). */
export function meter(f: Fetch) {
  let bytes = 0;
  return { fetch: (async (u, i) => { const r = await f(u, i); bytes += new TextEncoder().encode(await r.clone().text()).length; return r; }) as Fetch, bytes: () => bytes };
}

/** Builds the release entry for `binary`: vendor-signed (the release key), then approved by the second key unless `approve: false` (an attacker who stole only the release key). */
export const makeEntry = (e: Env, binary: Uint8Array, version = VERSION, o: { approve?: boolean } = {}): ReleaseEntry => {
  const signed = signEntry({
    app: APP, version, platform: PLATFORM, sha256: sha256(binary), size: binary.length,
    url: `${e.updateUrl}/download/${APP}/${version}/${PLATFORM}`, publishedAt: new Date((e.now ?? Date.now)()).toISOString(), vendorKeyId: e.vendor.keyId }, e.vendor.secretKey);
  return e.approver && o.approve !== false ? approveEntry(signed, e.approver.secretKey) : signed;
};

const ok = async (what: string, r: Response) => { if (!r.ok) throw new Error(`${what}: ${r.status} ${await r.text()}`); return r; };
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Publish: sign, put on the update server, append to the log, register as approved with the monitor, and wait until k witnesses cosigned the head
 *  that contains it (otherwise a client run right after would, correctly, fail INSUFFICIENT_COSIGS). */
export async function publish(e: Env, binary = GOOD, version = VERSION, waitMs = 15000) {
  const entry = makeEntry(e, binary, version);
  await ok("update server", await e.fetch(`${e.updateUrl}/admin/release`, { method: "POST", body: JSON.stringify({ entry, binary: Buffer.from(binary).toString("base64") }) }));
  const r = await ok("log rejected the release", await e.fetch(`${e.logUrl}/entries`, { method: "POST", body: JSON.stringify(entry) }));
  const { sth } = (await r.json()) as { sth: { treeSize: number } };
  if (e.monitor) await ok("monitor", await e.fetch(`${e.monitor.url}/approved`, { method: "POST", headers: { authorization: `Bearer ${e.monitor.token}` },
    body: JSON.stringify({ app: entry.app, version: entry.version, platform: entry.platform, sha256: entry.sha256 }) }));
  await waitCosigned(e, sth.treeSize, waitMs);
  return entry;
}
export const seed = (e: Env) => publish(e);

/** Polls the log until the head at `size` carries >= k cosigs. Throws on timeout. */
export async function waitCosigned(e: Env, size: number, ms = 15000) {
  const end = Date.now() + ms;
  for (;;) {
    const h = (await (await e.fetch(`${e.logUrl}/sth/${size}`)).json()) as { cosigs?: unknown[] };
    if ((h.cosigs?.length ?? 0) >= e.verify.threshold) return;
    if (Date.now() > end) throw new Error(`head ${size} not cosigned by ${e.verify.threshold} witnesses within ${ms} ms`);
    if (e.settle) await e.settle(); else await wait(100);
  }
}

/** Compromised update server: serve `clientId` a different binary under the same manifest (attack 1). */
export const attackWith = (e: Env, clientId: string, binary: Uint8Array, manifest?: ReleaseEntry) =>
  e.fetch(`${e.updateUrl}/admin/target`, { method: "POST", body: JSON.stringify({ clientId, binary: Buffer.from(binary).toString("base64"), manifest }) });
export const attack1 = (e: Env, clientId: string) => attackWith(e, clientId, EVIL);
export const reset = (e: Env) => e.fetch(`${e.updateUrl}/admin/reset`, { method: "POST" });

/** One installed client: fetch manifest + binary from the update server, run ALL of §7.2 (verifyUpdate's checks), report what it saw to every witness. */
export async function runClient(e: Env, id: string): Promise<ClientResult> {
  const t0 = performance.now(), m = meter(e.fetch), now = e.now ?? Date.now;
  const manifest = (await (await e.fetch(`${e.updateUrl}/latest/${APP}/${PLATFORM}?client=${id}`)).json()) as ReleaseEntry;
  const bin = new Uint8Array(await (await e.fetch(`${manifest.url}?client=${id}`)).arrayBuffer());
  const cfg: VerifyConfig = { ...e.verify, logUrl: e.logFor?.(id) ?? e.verify.logUrl, expected: { app: APP, platform: PLATFORM, installedVersion: INSTALLED } };
  const h0 = performance.now(); sha256(bin); const hashMs = performance.now() - h0; // the hash is recomputed inside checkUpdate; this isolates its cost
  const { checks, sth } = await checkUpdate(bin, manifest, cfg, { fetch: m.fetch, now });
  const verdict = verdictOf(checks, manifest, sth);
  const seen = sha256(bin), ms = performance.now() - t0;
  const obs: Observation = { app: manifest.app, version: manifest.version, platform: manifest.platform, sha256: seen, sthRoot: sth?.rootHash ?? "", sthSize: sth?.treeSize ?? 0,
    clientPseudonym: createHash("sha256").update(`secret-${id}`).update(manifest.app).digest("hex"), observedAt: new Date(now()).toISOString() };
  await reportObservation(obs, cfg, { fetch: e.fetch, now }).catch(() => {});
  return { id, version: manifest.version, state: verdict.ok ? "verified" : "blocked", reason: verdict.ok ? undefined : verdict.reason, detail: verdict.ok ? undefined : verdict.detail,
    sha256: seen, checks, ms, hashMs, networkMs: ms - hashMs, bytes: m.bytes() };
}
export const runFleet = (e: Env, n = 12) => Promise.all(clientIds(n).map((id) => runClient(e, id)));
