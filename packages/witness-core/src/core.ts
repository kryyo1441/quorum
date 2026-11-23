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
export type ObservedSet = { logged: Observation[]; seen: Observation[] };
export type WitnessSnapshot = { last?: STH; heads: STH[]; alerts: SplitViewAlert[]; forks?: SplitViewAlert[]; observations: ObservedSet[] | Observation[] };
export type HeadResult =
  | { status: "cosigned"; sth: STH }                    // sth = the verified head, carrying this witness's new cosig
  | { status: "unchanged" | "behind" | "error" | "rejected"; detail?: string }
  | { status: "inconsistent"; alert: SplitViewAlert };  // refused to cosign

export type AlertFilter = { app?: string; version?: string; platform?: string; sha256?: string };
const forkKey = (a: STH, b: STH) => [a.rootHash, b.rootHash].sort().join(":") + `@${a.treeSize}/${b.treeSize}`; // one alert per pair of conflicting heads
const ANY = "*"; // INCONSISTENT_STH is about the whole log, not one release. Scope comes from the alert KIND, never from this string (a client can send app="*").
// Public input must not be able to grow state without bound, and must not be able to push out what matters.
const MAX_SEEN = 32, MAX_LOGGED = 256, MAX_RELEASES = 10_000, MAX_ALERTS = 2_000, MAX_FORKS = 1_000, MAX_FIELD = 256;
const valid = (o: Observation) => [o.app, o.version, o.platform].every((x) => x.length > 0 && x.length <= MAX_FIELD && x !== ANY) && /^[0-9a-f]{64}$/.test(o.sha256);
const relKey = (r: { app: string; version: string; platform: string }) => `${r.app}\0${r.version}\0${r.platform}`;

/** What the witness has been told about one release. `logged` = hashes the AUTHENTICATED log listing holds (bounded by what the vendor actually published, so junk cannot fill it);
 *  `seen` = hashes reported by clients that the log does not (yet) hold, first-come and small. Blocking decisions come from these two sets, never from the alert history. */
type Rel = { logged: Map<string, Observation>; seen: Map<string, Observation> };

export class WitnessCore {
  private last?: STH;                        // last verified head (no cosigs)
  private lastCosigned?: STH;                // that head with our cosig, served at /sth
  private lastCosignAt = 0;
  private readonly heads = new Map<number, STH>(); // every log-signed head ever shown to us, by size: conflicts are proof of a fork
  private all: SplitViewAlert[] = [];              // evidence for the dashboard, bounded; NEVER consulted to decide whether a client is blocked
  private readonly forkList: SplitViewAlert[] = []; // fork evidence is kept separately and is not subject to the alert cap
  private readonly obs = new Map<string, Rel>();
  /** Called after every state change; the service persists `snapshot()` here so a restart does not forget the last verified head (no trust-on-first-use twice). */
  onChange?: () => void;
  /** Awaited BEFORE a cosignature is released: a witness that cannot durably record the head it is about to sign must not sign it (a crash would let it sign a conflicting head after restart). */
  persist?: (s: WitnessSnapshot) => Promise<void>;
  private chain: Promise<unknown> = Promise.resolve(); // head processing is strictly one at a time

  constructor(readonly cfg: WitnessConfig, private readonly d: WitnessDeps) {}

  head(): STH | undefined { return this.lastCosigned; }
  /** Demo reset: forget alerts and the observation index. Keeps the verified head history, so a fork can still be detected afterwards. */
  reset() { this.all = []; this.forkList.length = 0; this.forks.clear(); this.obs.clear(); this.onChange?.(); }

  /** Everything that must survive a restart: the last verified head, every log-signed head seen, alerts, fork evidence, and what was observed per release. */
  snapshot(): WitnessSnapshot {
    return { last: this.last, heads: [...this.heads.values()], alerts: [...this.all], forks: [...this.forkList],
      observations: [...this.obs.values()].map((r) => ({ logged: [...r.logged.values()], seen: [...r.seen.values()] })) };
  }
  /** Load a snapshot into a fresh core. The cosig is re-issued on the next heartbeat (lastCosignAt stays 0). Accepts the older flat shape too. */
  restore(s: WitnessSnapshot) {
    this.last = s.last;
    for (const h of s.heads) this.heads.set(h.treeSize, h);
    const old = s.alerts.filter((a) => a.kind === "INCONSISTENT_STH");
    this.all = s.alerts.filter((a) => a.kind !== "INCONSISTENT_STH");
    for (const a of [...(s.forks ?? []), ...old]) { this.forkList.push(a); this.forks.set(forkKey(a.evidence.headA as STH, a.evidence.headB as STH), a); }
    for (const e of s.observations) {
      const sets: ObservedSet = "logged" in e ? e : { logged: [], seen: [e] };
      for (const o of [...sets.logged, ...sets.seen]) this.rel(o).seen.set(o.sha256, o);
      for (const o of sets.logged) { const r = this.rel(o); r.seen.delete(o.sha256); r.logged.set(o.sha256, o); }
    }
  }
  private rel(r: { app: string; version: string; platform: string }): Rel {
    const k = relKey(r);
    let x = this.obs.get(k);
    if (!x) {
      if (this.obs.size >= MAX_RELEASES) { // make room by dropping a release nothing authenticated is known about; real releases (with a logged hash) are never evicted by junk
        for (const [kk, v] of this.obs) if (v.logged.size === 0) { this.obs.delete(kk); break; }
      }
      x = { logged: new Map(), seen: new Map() }; this.obs.set(k, x);
    }
    return x;
  }
  private alert(kind: SplitViewAlert["kind"], rel: { app: string; version: string; platform: string }, evidence: Record<string, unknown>, store = true): SplitViewAlert {
    const a: SplitViewAlert = { kind, ...rel, evidence, raisedBy: this.cfg.id, raisedAt: this.d.now().toISOString() };
    if (!store) return a;
    if (kind === "INCONSISTENT_STH") { if (this.forkList.length < MAX_FORKS) this.forkList.push(a); }
    else { this.all.push(a); if (this.all.length > MAX_ALERTS) this.all.shift(); } // ring: the newest evidence replaces the oldest, detection is unaffected either way
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
   *  Public and unauthenticated, so everything is bounded (see the constants). A hash the AUTHENTICATED log listing holds goes in `logged`, which unverified junk cannot crowd out. */
  async observe(o: Observation): Promise<SplitViewAlert[]> {
    if (!valid(o)) return [];
    const r = this.rel(o), at = { app: o.app, version: o.version, platform: o.platform };
    if (r.logged.has(o.sha256) || r.seen.has(o.sha256)) return [];
    let held: string[] | null;
    try { held = await this.d.logHashes(o.app, o.version, o.platform); } catch { held = null; } // unreachable, or the listing does not match the head
    if (r.logged.has(o.sha256) || r.seen.has(o.sha256)) return []; // another report of the same hash finished while we waited
    const others = [...r.logged.values(), ...r.seen.values()];    // read AFTER the await: concurrent reports must see each other
    const raised: SplitViewAlert[] = [];
    if (held?.includes(o.sha256)) { if (r.logged.size < MAX_LOGGED) r.logged.set(o.sha256, o); }
    else {
      if (r.seen.size >= MAX_SEEN) return []; // full of unverified reports: ignored (a LOGGED hash never reaches this branch, so it can never be crowded out)
      r.seen.set(o.sha256, o);
      if (held) raised.push(this.alert("NOT_IN_LOG", at, { sha256: o.sha256, observation: o })); // only when the log answered and does not hold it
    }
    if (others[0]) raised.push(this.alert("HASH_MISMATCH", at, { hashes: [others[0].sha256, o.sha256], observationA: others[0], observationB: o }));
    this.onChange?.();
    return raised;
  }

  /** Alerts for a release. Without `sha256` (the dashboard): fork evidence plus the recorded evidence for the release.
   *  With `sha256` (what a client asks): the decision is computed NOW from what the witness knows, never from the alert history, so a full or churning alert list cannot hide a conflict:
   *   - INCONSISTENT_STH: always (only the log's own signatures can cause it);
   *   - this hash was reported and the AUTHENTICATED log listing does not hold it (or cannot be checked): NOT_IN_LOG, so a premature report resolves itself once the release is logged;
   *   - the log holds two or more of the hashes reported for the release and this is one of them: HASH_MISMATCH (a real equivocation);
   *   - a bogus hash reported for the same release blocks nobody who holds the logged one.
   *  Costs at most ONE listing lookup per request. */
  async alerts(f: AlertFilter = {}): Promise<SplitViewAlert[]> {
    const m = this.all.filter((a) => (!f.app || a.app === f.app) && (!f.version || a.version === f.version) && (!f.platform || a.platform === f.platform));
    if (f.sha256 === undefined) return [...this.forkList, ...m];
    const out = [...this.forkList];
    if (!f.app || !f.version || !f.platform) return out;
    const at = { app: f.app, version: f.version, platform: f.platform }, r = this.obs.get(relKey(at)), h = f.sha256;
    if (!r) return out;
    const block = (kind: SplitViewAlert["kind"], ev: Record<string, unknown>) => out.push(this.alert(kind, at, ev, false));
    if (!r.logged.has(h) && r.seen.has(h)) {
      let held: string[] | null;
      try { held = await this.d.logHashes(f.app, f.version, f.platform); } catch { held = null; }
      if (held === null) { block("NOT_IN_LOG", { sha256: h, note: "reported by a client and the log's listing cannot be authenticated: failing closed" }); return out; }
      if (held.includes(h)) { const o = r.seen.get(h)!; r.seen.delete(h); if (r.logged.size < MAX_LOGGED) r.logged.set(h, o); this.onChange?.(); }
      else { block("NOT_IN_LOG", { sha256: h, note: "reported by a client and not in the log" }); return out; }
    }
    if (r.logged.has(h) && r.logged.size >= 2) block("HASH_MISMATCH", { hashes: [...r.logged.keys()], note: "the log holds more than one hash for this release" });
    return out;
  }
}
