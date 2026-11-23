// Witness logic per SPEC §8. Pure: the network is injected, so every branch is testable and the service stays thin.
import { cosign, verifyConsistency, verifyLogSig } from "@uw/log-core";
import type { Observation, SplitViewAlert, STH } from "@uw/shared";

export type WitnessConfig = {
  id: string; secretKey: string;
  logId: string; logPublicKey: string; // PINNED by the operator, never fetched from the log being witnessed
  heartbeatMs: number;                 // re-cosign the unchanged head this often so cosig timestamps stay fresh (clients check freshness on them)
};
export type WitnessDeps = {
  consistency(from: number, to: number): Promise<string[]>;                         // from the log; throws when unreachable
  logHashes(app: string, version: string, platform: string): Promise<string[]>;     // sha256 values the log holds for a release; throws when unreachable
  now(): Date;
};
export type WitnessSnapshot = { last?: STH; heads: STH[]; alerts: SplitViewAlert[]; observations: Observation[] };
export type HeadResult =
  | { status: "cosigned"; sth: STH }                    // sth = the verified head, carrying this witness's new cosig
  | { status: "unchanged" | "behind" | "error" | "rejected"; detail?: string }
  | { status: "inconsistent"; alert: SplitViewAlert };  // refused to cosign

export type AlertFilter = { app?: string; version?: string; platform?: string; sha256?: string };
const forkKey = (a: STH, b: STH) => [a.rootHash, b.rootHash].sort().join(":") + `@${a.treeSize}/${b.treeSize}`; // one alert per pair of conflicting heads
const ANY = "*"; // INCONSISTENT_STH is about the whole log, not one release. Scope comes from the alert KIND, never from this string (a client can send app="*").
const MAX_HASHES_PER_RELEASE = 32, MAX_RELEASES = 10_000, MAX_ALERTS = 2_000, MAX_FIELD = 256; // public input must not be able to grow state without bound
const valid = (o: Observation) => [o.app, o.version, o.platform].every((x) => x.length > 0 && x.length <= MAX_FIELD && x !== ANY) && /^[0-9a-f]{64}$/.test(o.sha256);

export class WitnessCore {
  private last?: STH;                        // last verified head (no cosigs)
  private lastCosigned?: STH;                // that head with our cosig, served at /sth
  private lastCosignAt = 0;
  private readonly heads = new Map<number, STH>(); // every log-signed head ever shown to us, by size: conflicts are proof of a fork
  private readonly all: SplitViewAlert[] = [];
  private readonly obs = new Map<string, Map<string, Observation>>(); // release -> sha256 -> first observation
  /** Called after every state change; the service persists `snapshot()` here so a restart does not forget the last verified head (no trust-on-first-use twice). */
  onChange?: () => void;
  /** Awaited BEFORE a cosignature is released: a witness that cannot durably record the head it is about to sign must not sign it (a crash would let it sign a conflicting head after restart). */
  persist?: (s: WitnessSnapshot) => Promise<void>;
  private chain: Promise<unknown> = Promise.resolve(); // head processing is strictly one at a time
  private readonly unchecked: Observation[] = [];     // observations whose log lookup failed: retried instead of forgotten

  constructor(readonly cfg: WitnessConfig, private readonly d: WitnessDeps) {}

  head(): STH | undefined { return this.lastCosigned; }
  /** Demo reset: forget alerts and the observation index. Keeps the verified head history, so a fork can still be detected afterwards. */
  reset() { this.all.length = 0; this.forks.clear(); this.obs.clear(); this.onChange?.(); }

  /** Everything that must survive a restart: the last verified head, every log-signed head seen, alerts, and the observation index. */
  snapshot(): WitnessSnapshot {
    return { last: this.last, heads: [...this.heads.values()], alerts: [...this.all], observations: [...this.obs.values()].flatMap((m) => [...m.values()]) };
  }
  /** Load a snapshot into a fresh core. The cosig is re-issued on the next heartbeat (lastCosignAt stays 0). */
  restore(s: WitnessSnapshot) {
    this.last = s.last;
    for (const h of s.heads) this.heads.set(h.treeSize, h);
    this.all.push(...s.alerts);
    for (const a of s.alerts) if (a.kind === "INCONSISTENT_STH") this.forks.set(forkKey(a.evidence.headA as STH, a.evidence.headB as STH), a);
    for (const o of s.observations) { const k = `${o.app}\0${o.version}\0${o.platform}`, m = this.obs.get(k) ?? new Map<string, Observation>(); m.set(o.sha256, o); this.obs.set(k, m); }
  }
  private alert(kind: SplitViewAlert["kind"], rel: { app: string; version: string; platform: string }, evidence: Record<string, unknown>): SplitViewAlert {
    const a: SplitViewAlert = { kind, ...rel, evidence, raisedBy: this.cfg.id, raisedAt: this.d.now().toISOString() };
    if (kind !== "INCONSISTENT_STH" && this.all.length >= MAX_ALERTS) return a; // flood guard: the evidence that matters (a fork) is always kept
    this.all.push(a);
    this.onChange?.();
    return a;
  }
  private readonly forks = new Map<string, SplitViewAlert>();
  private fork(a: STH, b: STH): HeadResult {
    const key = forkKey(a, b);
    let alert = this.forks.get(key);
    if (!alert) { alert = this.alert("INCONSISTENT_STH", { app: ANY, version: ANY, platform: ANY }, { headA: a, headB: b }); this.forks.set(key, alert); }
    return { status: "inconsistent", alert };
  }

  /** A head from the log's poll or from a peer's gossip. Cosigns only a head that is validly signed AND consistent with everything seen. */
  onHead(h: STH): Promise<HeadResult> {
    // One head at a time: the consistency check awaits the network, and two interleaved checks anchored on the same `last` could each pass and then cosign out of order.
    const r = this.chain.then(() => this.process(h));
    this.chain = r.catch(() => {});
    return r;
  }
  private async process(h: STH): Promise<HeadResult> {
    const { logId, logPublicKey } = this.cfg;
    const sth: STH = { ...h, cosigs: [] };
    if (h.logId !== logId || !verifyLogSig(sth, logPublicKey)) return { status: "rejected", detail: "not a head signed by the pinned log key" };

    const prior = this.heads.get(sth.treeSize);
    if (prior && prior.rootHash !== sth.rootHash) return this.fork(prior, sth); // same size, two roots, both log-signed
    if (!prior) { this.heads.set(sth.treeSize, sth); this.onChange?.(); }

    const last = this.last;
    if (!last) return this.cosignHead(sth); // first sight: trust on first use (persisted state removes this after the first run)
    if (sth.treeSize === last.treeSize) // same root (checked above)
      return this.d.now().getTime() - this.lastCosignAt >= this.cfg.heartbeatMs ? this.cosignHead(sth) : { status: "unchanged" };

    const [from, to] = sth.treeSize < last.treeSize ? [sth, last] : [last, sth];
    let path: string[];
    try { path = await this.d.consistency(from.treeSize, to.treeSize); }
    catch (e) { return { status: "error", detail: `consistency proof unavailable: ${e instanceof Error ? e.message : e}` }; }
    if (!Array.isArray(path) || !verifyConsistency(from.treeSize, to.treeSize, from.rootHash, to.rootHash, path)) return this.fork(last, sth);
    if (sth.treeSize < last.treeSize) return { status: "behind" }; // consistent but old: never cosign below what we already cosigned
    return this.cosignHead(sth);
  }

  private async cosignHead(sth: STH): Promise<HeadResult> {
    const prev = { last: this.last, at: this.lastCosignAt };
    this.last = sth;
    this.lastCosignAt = this.d.now().getTime();
    try { await this.persist?.(this.snapshot()); }
    catch (e) {
      this.last = prev.last; this.lastCosignAt = prev.at; // nothing was signed, nothing is remembered
      return { status: "error", detail: `could not persist state, refusing to cosign: ${e instanceof Error ? e.message : e}` };
    }
    this.lastCosigned = { ...sth, cosigs: [cosign(sth, this.cfg.id, this.cfg.secretKey, this.d.now().toISOString())] };
    return { status: "cosigned", sth: this.lastCosigned };
  }

  /** §8 Observations: more than one distinct sha256 for a release -> HASH_MISMATCH; a hash the log does not hold -> NOT_IN_LOG.
   *  Public and unauthenticated, so everything is bounded: field sizes, hashes per release, releases, alerts. Alerts are linear (new hash vs the first one seen). */
  async observe(o: Observation): Promise<SplitViewAlert[]> {
    if (!valid(o)) return [];
    const rel = { app: o.app, version: o.version, platform: o.platform };
    const k = `${o.app}\0${o.version}\0${o.platform}`;
    let byHash = this.obs.get(k);
    if (!byHash) { if (this.obs.size >= MAX_RELEASES) return []; byHash = new Map(); this.obs.set(k, byHash); }
    if (byHash.has(o.sha256) || byHash.size >= MAX_HASHES_PER_RELEASE) return [];
    const first = byHash.values().next().value as Observation | undefined;
    byHash.set(o.sha256, o);
    this.onChange?.();
    const raised: SplitViewAlert[] = [];
    if (first) raised.push(this.alert("HASH_MISMATCH", rel, { hashes: [first.sha256, o.sha256], observationA: first, observationB: o }));
    try { if (!(await this.d.logHashes(o.app, o.version, o.platform)).includes(o.sha256)) raised.push(this.alert("NOT_IN_LOG", rel, { sha256: o.sha256, observation: o })); }
    catch { this.unchecked.push(o); } // log unreachable or its listing does not match the signed head: cannot say, retry later
    return raised;
  }

  /** Re-evaluates what was derived from the log's listing, so a premature or failed lookup cannot stick: a NOT_IN_LOG alert is withdrawn once the hash IS in the log
   *  (a release observed before it was published), and an observation whose lookup failed is checked again. */
  private async refresh() {
    const cache = new Map<string, string[] | null>();
    const held = async (r: { app: string; version: string; platform: string }) => {
      const k = `${r.app}\0${r.version}\0${r.platform}`;
      if (!cache.has(k)) cache.set(k, await this.d.logHashes(r.app, r.version, r.platform).catch(() => null));
      return cache.get(k)!;
    };
    for (let i = this.all.length - 1; i >= 0; i--) {
      const a = this.all[i];
      if (a.kind === "NOT_IN_LOG" && (await held(a))?.includes(a.evidence.sha256 as string)) { this.all.splice(i, 1); this.onChange?.(); }
    }
    for (const o of this.unchecked.splice(0)) {
      const l = await held(o);
      if (l === null) this.unchecked.push(o);
      else if (!l.includes(o.sha256) && !this.all.some((a) => a.kind === "NOT_IN_LOG" && a.evidence.sha256 === o.sha256 && a.app === o.app && a.version === o.version && a.platform === o.platform))
        this.alert("NOT_IN_LOG", { app: o.app, version: o.version, platform: o.platform }, { sha256: o.sha256, observation: o });
    }
  }

  /** Alerts for a release. With `sha256` (what a client asks) only alerts that concern THAT binary come back, so one bad actor
   *  reporting a random hash cannot block every client of a release (docs/spec-amendments.md):
   *   - INCONSISTENT_STH: always (only the log's own signatures can cause it);
   *   - NOT_IN_LOG: only for the same hash, and only while the log still does not hold it;
   *   - HASH_MISMATCH: only when the log holds two or more of the hashes observed for the release, including this one (a real equivocation).
   *  "The log holds" is checked against the log's listing AUTHENTICATED against the head this witness cosigned (see runner.ts), never the raw listing. */
  async alerts(f: AlertFilter = {}): Promise<SplitViewAlert[]> {
    await this.refresh();
    const m = this.all.filter((a) => a.kind === "INCONSISTENT_STH" || ((!f.app || a.app === f.app) && (!f.version || a.version === f.version) && (!f.platform || a.platform === f.platform)));
    if (f.sha256 === undefined) return m;
    const out: SplitViewAlert[] = [], seenRelease = new Set<string>();
    for (const a of m) {
      if (a.kind === "NOT_IN_LOG") { if (a.evidence.sha256 === f.sha256) out.push(a); }
      else if (a.kind === "HASH_MISMATCH") {
        const k = `${a.app}\0${a.version}\0${a.platform}`;
        if (seenRelease.has(k)) continue; // one blocking alert per release is enough
        const observed = [...(this.obs.get(k)?.keys() ?? [])];
        let logged = observed;
        try { const l = await this.d.logHashes(a.app, a.version, a.platform); logged = observed.filter((x) => l.includes(x)); } catch { /* unreachable: fail closed, treat all as logged */ }
        if (logged.length >= 2 && logged.includes(f.sha256)) { out.push(a); seenRelease.add(k); }
      } else out.push(a);
    }
    return out;
  }
}
