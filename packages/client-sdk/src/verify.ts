// verifyUpdate per SPEC §7.2. Browser-safe (no node imports). Never throws: every error is a failed check (fail closed).
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { leafHashOfEntry, verifyCosig, verifyEntry, verifyInclusion, verifyLogSig } from "@uw/log-core";
import { ReleaseEntry as ReleaseEntrySchema, STH, type FailReason, type Observation, type ReleaseEntry } from "@uw/shared";

export interface VerifyConfig {
  logUrl: string;
  witnesses: { id: string; url: string; publicKey: string }[];
  threshold: number;          // k of n cosignatures, default 2. Must be an integer in 1..n.
  vendorPublicKeys: Record<string, string>;
  logPublicKey: string;
  maxAgeMs?: number;          // human-approved addition (docs/spec-amendments.md): default 24h, demo 5 min. Must be finite and > 0.
  /** Human-approved addition (2026-11-22). What this install is: pins app + platform and (optionally) blocks downgrades.
   *  Without it the "target" check is SKIPPED, and an old or other-platform release that is in the log would verify. */
  expected?: { app: string; platform: string; installedVersion?: string };
}
export type Verdict =
  | { ok: true; entry: ReleaseEntry; sth: STH }
  | { ok: false; reason: FailReason; detail: string };
export type CheckId = "hash" | "vendorSig" | "target" | "inclusion" | "logSig" | "cosigs" | "fresh" | "noSplitView";
export type Check = { id: CheckId; label: string; status: "pass" | "fail" | "skip"; reason?: FailReason; detail?: string };

export type Deps = { fetch: typeof fetch; now: () => number };
const defaults = (): Deps => ({ fetch: (...a) => globalThis.fetch(...a), now: Date.now });
const TIMEOUT_MS = 5000, DAY_MS = 24 * 3600 * 1000, MAX_SKEW_MS = 5 * 60 * 1000;
const errText = (e: unknown) => (e instanceof Error ? e.message : String(e));

const IDS: CheckId[] = ["hash", "vendorSig", "target", "inclusion", "logSig", "cosigs", "fresh", "noSplitView"];
const LABELS: Record<CheckId, string> = {
  hash: "File hash matches the manifest", vendorSig: "Vendor signature valid for a known key",
  target: "Release is for this install and newer than the installed version",
  inclusion: "Inclusion proof verifies against the head", logSig: "Head is signed by the log",
  cosigs: "Head has enough valid witness cosignatures", fresh: "Enough cosignatures are fresh", noSplitView: "No open split-view alert",
};

// ---- version comparison (semver core numeric; any prerelease sorts below its release) ----
const SEMVER = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;
/** <0, 0, >0, or undefined when either side is not a semver. ponytail: prereleases compare as plain strings, not per-identifier. */
export function compareVersions(a: string, b: string): number | undefined {
  const x = SEMVER.exec(a), y = SEMVER.exec(b);
  if (!x || !y) return undefined;
  for (let i = 1; i <= 3; i++) { const d = Number(x[i]) - Number(y[i]); if (d !== 0) return d; }
  if (x[4] === y[4]) return 0;
  if (x[4] === undefined) return 1;
  if (y[4] === undefined) return -1;
  return x[4] < y[4] ? -1 : 1;
}

const WELL_FORMED = (s: string) => !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s); // no lone surrogates
const sane = (n: unknown, ok: (n: number) => boolean) => typeof n === "number" && Number.isFinite(n) && ok(n);

async function get(d: Deps, url: string): Promise<{ status: number; body: unknown }> {
  const r = await d.fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  return { status: r.status, body: r.ok ? await r.json() : undefined };
}

/** Runs every check in §7.2 order and reports each one. Later checks are skipped only when a dependency (the head) is missing. */
export async function checkUpdate(binary: Uint8Array, manifest: ReleaseEntry, cfg: VerifyConfig, d: Deps = defaults()): Promise<{ checks: Check[]; sth?: STH }> {
  const out: Check[] = [];
  const add = (id: CheckId, status: Check["status"], reason?: FailReason, detail?: string) => out.push({ id, label: LABELS[id], status, reason, detail });
  const fail = (id: CheckId, reason: FailReason, detail: string) => add(id, "fail", reason, detail);

  // 0. a malformed manifest never reaches the network or the crypto
  const parsed = ReleaseEntrySchema.safeParse(manifest);
  if (!parsed.success || !Object.values(manifest).every((v) => typeof v !== "string" || WELL_FORMED(v))) {
    for (const id of IDS) id === "vendorSig" ? fail(id, "BAD_VENDOR_SIG", "malformed manifest") : add(id, "skip");
    return { checks: out };
  }

  // 1. hash
  const seen = bytesToHex(sha256(binary));
  seen === manifest.sha256 ? add("hash", "pass") : fail("hash", "HASH_MISMATCH", `binary is ${seen}, manifest says ${manifest.sha256}`);

  // 2. vendor signature
  const vk = Object.hasOwn(cfg.vendorPublicKeys, manifest.vendorKeyId) ? cfg.vendorPublicKeys[manifest.vendorKeyId] : undefined;
  if (!vk) fail("vendorSig", "BAD_VENDOR_SIG", `unknown vendor key id "${manifest.vendorKeyId}"`);
  else verifyEntry(manifest, vk) ? add("vendorSig", "pass") : fail("vendorSig", "BAD_VENDOR_SIG", "signature does not verify");

  // 2b. target: every release ever logged keeps a valid proof against every later head, so without this a downgrade verifies (§10 #6).
  const ex = cfg.expected;
  if (!ex) add("target", "skip", undefined, "no expected target configured: downgrade and cross-app/platform substitution are NOT checked");
  else if (manifest.app !== ex.app || manifest.platform !== ex.platform)
    fail("target", "NOT_IN_LOG", `manifest is for ${manifest.app} ${manifest.platform}, this install is ${ex.app} ${ex.platform}`);
  else if (ex.installedVersion === undefined) add("target", "pass");
  else {
    const c = compareVersions(manifest.version, ex.installedVersion);
    if (c === undefined) fail("target", "STALE_STH", `cannot compare versions "${manifest.version}" and "${ex.installedVersion}"`);
    else if (c <= 0) fail("target", "STALE_STH", `manifest version ${manifest.version} is not newer than installed ${ex.installedVersion} (downgrade or replay)`);
    else add("target", "pass");
  }

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

    const ids = cfg.witnesses.map((w) => w.id), keys = cfg.witnesses.map((w) => w.publicKey);
    const cfgErr = !sane(cfg.threshold, (n) => Number.isInteger(n) && n >= 1 && n <= cfg.witnesses.length) ? `threshold ${cfg.threshold} must be an integer in 1..${cfg.witnesses.length}`
      : new Set(ids).size !== ids.length || new Set(keys).size !== keys.length ? "duplicate witness id or public key in config" : undefined;
    // newest valid cosig per witness; cosigs from unconfigured witnesses are ignored
    const valid = new Map<string, number>();
    for (const c of sth.cosigs) {
      const w = cfg.witnesses.find((x) => x.id === c.witnessId), t = Date.parse(c.timestamp);
      if (w && Number.isFinite(t) && verifyCosig(sth, c, w.publicKey) && !(valid.get(w.id)! >= t)) valid.set(w.id, t);
    }
    if (cfgErr) { fail("cosigs", "INSUFFICIENT_COSIGS", `invalid config: ${cfgErr}`); add("fresh", "skip"); }
    else {
      valid.size >= cfg.threshold ? add("cosigs", "pass", undefined, `${valid.size} valid of ${cfg.witnesses.length}, need ${cfg.threshold}`)
        : fail("cosigs", "INSUFFICIENT_COSIGS", `${valid.size} valid cosignatures, need ${cfg.threshold}`);
      const max = cfg.maxAgeMs ?? DAY_MS;
      if (valid.size < cfg.threshold) add("fresh", "skip");
      else if (!sane(max, (n) => n > 0)) fail("fresh", "STALE_STH", `invalid maxAgeMs ${max}: must be finite and > 0`);
      else {
        const now = d.now();
        const fresh = [...valid.values()].filter((t) => now - t <= max && t - now <= MAX_SKEW_MS).length; // small future skew only
        fresh >= cfg.threshold ? add("fresh", "pass") : fail("fresh", "STALE_STH", `only ${fresh} cosignatures within ${max} ms, need ${cfg.threshold}`);
      }
    }
  }

  // 5. no open alert from ANY witness; any unreachable witness fails closed (docs/spec-amendments.md)
  const q = `app=${encodeURIComponent(manifest.app)}&version=${encodeURIComponent(manifest.version)}&platform=${encodeURIComponent(manifest.platform)}&sha256=${manifest.sha256}`; // sha256: only alerts about THIS binary block it (docs/spec-amendments.md)
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
