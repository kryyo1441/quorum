// verifyUpdate per SPEC §7.2. Browser-safe (no node imports). Never throws: every error is a failed check (fail closed).
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { leafHashOfEntry, verifyCosig, verifyEntry, verifyInclusion, verifyLogSig } from "@uw/log-core";
import { STH, type FailReason, type Observation, type ReleaseEntry } from "@uw/shared";

export interface VerifyConfig {
  logUrl: string;
  witnesses: { id: string; url: string; publicKey: string }[];
  threshold: number;          // k of n cosignatures, default 2
  vendorPublicKeys: Record<string, string>;
  logPublicKey: string;
  maxAgeMs?: number;          // human-approved addition (docs/spec-amendments.md): default 24h, demo 5 min
}
export type Verdict =
  | { ok: true; entry: ReleaseEntry; sth: STH }
  | { ok: false; reason: FailReason; detail: string };
export type CheckId = "hash" | "vendorSig" | "inclusion" | "logSig" | "cosigs" | "fresh" | "noSplitView";
export type Check = { id: CheckId; label: string; status: "pass" | "fail" | "skip"; reason?: FailReason; detail?: string };

export type Deps = { fetch: typeof fetch; now: () => number };
const defaults = (): Deps => ({ fetch: (...a) => globalThis.fetch(...a), now: Date.now });
const TIMEOUT_MS = 5000, DAY_MS = 24 * 3600 * 1000;
const errText = (e: unknown) => (e instanceof Error ? e.message : String(e));

async function get(d: Deps, url: string): Promise<{ status: number; body: unknown }> {
  const r = await d.fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  return { status: r.status, body: r.ok ? await r.json() : undefined };
}

const LABELS: Record<CheckId, string> = {
  hash: "File hash matches the manifest", vendorSig: "Vendor signature valid for a known key",
  inclusion: "Inclusion proof verifies against the head", logSig: "Head is signed by the log",
  cosigs: "Head has enough valid witness cosignatures", fresh: "Enough cosignatures are fresh", noSplitView: "No open split-view alert",
};

/** Runs every check in §7.2 order and reports each one. Later checks are skipped only when a dependency (the head) is missing. */
export async function checkUpdate(binary: Uint8Array, manifest: ReleaseEntry, cfg: VerifyConfig, d: Deps = defaults()): Promise<{ checks: Check[]; sth?: STH }> {
  const out: Check[] = [];
  const add = (id: CheckId, status: Check["status"], reason?: FailReason, detail?: string) => out.push({ id, label: LABELS[id], status, reason, detail });
  const fail = (id: CheckId, reason: FailReason, detail: string) => add(id, "fail", reason, detail);

  // 1. hash
  const seen = bytesToHex(sha256(binary));
  seen === manifest.sha256 ? add("hash", "pass") : fail("hash", "HASH_MISMATCH", `binary is ${seen}, manifest says ${manifest.sha256}`);

  // 2. vendor signature
  const vk = cfg.vendorPublicKeys[manifest.vendorKeyId];
  if (!vk) fail("vendorSig", "BAD_VENDOR_SIG", `unknown vendor key id "${manifest.vendorKeyId}"`);
  else verifyEntry(manifest, vk) ? add("vendorSig", "pass") : fail("vendorSig", "BAD_VENDOR_SIG", "signature does not verify");

  // 3. inclusion: get the head, then the proof AT THAT HEAD's size. Size and root come from the head, never from the proof response.
  let sth: STH | undefined;
  try {
    const h = await get(d, `${cfg.logUrl}/sth`);
    const p = h.status === 200 ? STH.safeParse(h.body) : undefined;
    if (!p?.success) fail("inclusion", "NOT_IN_LOG", h.status === 200 ? "log returned a malformed head" : `log returned ${h.status} for the head`);
    else {
      sth = p.data;
      const leafHash = leafHashOfEntry(manifest);
      const r = await get(d, `${cfg.logUrl}/proof?leafHash=${leafHash}&treeSize=${sth.treeSize}`);
      const b = r.body as { leafIndex?: unknown; path?: unknown } | undefined;
      if (r.status === 404) fail("inclusion", "NOT_IN_LOG", "log has no such entry at the signed head");
      else if (r.status !== 200 || !b) fail("inclusion", "NOT_IN_LOG", `log returned ${r.status} for the proof`);
      else if (!Number.isInteger(b.leafIndex) || !Array.isArray(b.path) || !b.path.every((x) => typeof x === "string")) fail("inclusion", "BAD_INCLUSION_PROOF", "malformed proof");
      else verifyInclusion(leafHash, b.leafIndex as number, sth.treeSize, b.path as string[], sth.rootHash)
        ? add("inclusion", "pass") : fail("inclusion", "BAD_INCLUSION_PROOF", "proof does not reach the head's root");
    }
  } catch (e) { fail("inclusion", "NOT_IN_LOG", `log unreachable: ${errText(e)}`); }

  // 4. head checks
  if (!sth) { add("logSig", "skip"); add("cosigs", "skip"); add("fresh", "skip"); }
  else {
    verifyLogSig(sth, cfg.logPublicKey) ? add("logSig", "pass") : fail("logSig", "BAD_INCLUSION_PROOF", "head log signature invalid");
    const valid = new Map<string, number>(); // witnessId -> cosig time (distinct witnesses only)
    for (const c of sth.cosigs) {
      const w = cfg.witnesses.find((x) => x.id === c.witnessId);
      if (w && !valid.has(w.id) && verifyCosig(sth, c, w.publicKey)) valid.set(w.id, Date.parse(c.timestamp));
    }
    valid.size >= cfg.threshold ? add("cosigs", "pass", undefined, `${valid.size} valid of ${cfg.witnesses.length}, need ${cfg.threshold}`)
      : fail("cosigs", "INSUFFICIENT_COSIGS", `${valid.size} valid cosignatures, need ${cfg.threshold}`);
    if (valid.size < cfg.threshold) add("fresh", "skip");
    else {
      const max = cfg.maxAgeMs ?? DAY_MS, now = d.now();
      const fresh = [...valid.values()].filter((t) => now - t <= max && t - now <= max).length; // also rejects far-future stamps
      fresh >= cfg.threshold ? add("fresh", "pass") : fail("fresh", "STALE_STH", `only ${fresh} cosignatures within ${max} ms, need ${cfg.threshold}`);
    }
  }

  // 5. no open alert from ANY witness; any unreachable witness fails closed (docs/spec-amendments.md)
  const q = `app=${encodeURIComponent(manifest.app)}&version=${encodeURIComponent(manifest.version)}&platform=${encodeURIComponent(manifest.platform)}`;
  const results = await Promise.all(cfg.witnesses.map(async (w) => {
    try { const r = await get(d, `${w.url}/alerts?${q}`); return r.status === 200 && Array.isArray(r.body) ? { w, n: r.body.length, err: undefined } : { w, n: 0, err: `returned ${r.status}` }; }
    catch (e) { return { w, n: 0, err: errText(e) }; }
  }));
  const down = results.find((r) => r.err), open = results.find((r) => r.n > 0);
  if (open) fail("noSplitView", "SPLIT_VIEW", `witness ${open.w.id} has an open alert for ${manifest.app} ${manifest.version} ${manifest.platform}`);
  else if (down) fail("noSplitView", "INSUFFICIENT_COSIGS", `witness ${down.w.id} unreachable: ${down.err}`);
  else add("noSplitView", "pass");
  return { checks: out, sth };
}

export function verdictOf(checks: Check[], manifest: ReleaseEntry, sth?: STH): Verdict {
  const bad = checks.find((c) => c.status === "fail");
  if (bad) return { ok: false, reason: bad.reason!, detail: `${bad.label}: ${bad.detail}` };
  return sth ? { ok: true, entry: manifest, sth } : { ok: false, reason: "NOT_IN_LOG", detail: "no head" };
}

/** Frozen API (§7.1). Resolves ok only if every check passes; never rejects. */
export async function verifyUpdate(binary: Uint8Array, manifest: ReleaseEntry, cfg: VerifyConfig, d: Deps = defaults()): Promise<Verdict> {
  try { const { checks, sth } = await checkUpdate(binary, manifest, cfg, d); return verdictOf(checks, manifest, sth); }
  catch (e) { return { ok: false, reason: "NOT_IN_LOG", detail: `verification error: ${errText(e)}` }; }
}

export async function reportObservation(obs: Observation, cfg: VerifyConfig, d: Deps = defaults()): Promise<void> {
  const rs = await Promise.allSettled(cfg.witnesses.map(async (w) => {
    const r = await d.fetch(`${w.url}/observations`, { method: "POST", body: JSON.stringify(obs), signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (!r.ok) throw new Error(`${w.id} returned ${r.status}`);
  }));
  if (rs.length > 0 && rs.every((r) => r.status === "rejected")) throw new Error("no witness accepted the observation");
}
