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
export type HeadResult =
  | { status: "cosigned"; sth: STH }                    // sth = the verified head, carrying this witness's new cosig
  | { status: "unchanged" | "behind" | "error" | "rejected"; detail?: string }
  | { status: "inconsistent"; alert: SplitViewAlert };  // refused to cosign

export type AlertFilter = { app?: string; version?: string; platform?: string; sha256?: string };
const ANY = "*"; // INCONSISTENT_STH is about the whole log, not one release

export class WitnessCore {
  private last?: STH;                        // last verified head (no cosigs)
  private lastCosigned?: STH;                // that head with our cosig, served at /sth
  private lastCosignAt = 0;
  private readonly heads = new Map<number, STH>(); // every log-signed head ever shown to us, by size: conflicts are proof of a fork
  private readonly all: SplitViewAlert[] = [];
  private readonly obs = new Map<string, Map<string, Observation>>(); // release -> sha256 -> first observation
  // ponytail: all state is in memory, so a restart is trust-on-first-use again. Persist `last` + `heads` per witness to close that.

  constructor(readonly cfg: WitnessConfig, private readonly d: WitnessDeps) {}

  head(): STH | undefined { return this.lastCosigned; }
  private alert(kind: SplitViewAlert["kind"], rel: { app: string; version: string; platform: string }, evidence: Record<string, unknown>): SplitViewAlert {
    const a: SplitViewAlert = { kind, ...rel, evidence, raisedBy: this.cfg.id, raisedAt: this.d.now().toISOString() };
    this.all.push(a);
    return a;
  }
  private readonly forks = new Map<string, SplitViewAlert>();
  private fork(a: STH, b: STH): HeadResult {
    const key = [a.rootHash, b.rootHash].sort().join(":") + `@${a.treeSize}/${b.treeSize}`; // one alert per pair of conflicting heads
    let alert = this.forks.get(key);
    if (!alert) { alert = this.alert("INCONSISTENT_STH", { app: ANY, version: ANY, platform: ANY }, { headA: a, headB: b }); this.forks.set(key, alert); }
    return { status: "inconsistent", alert };
  }

  /** A head from the log's poll or from a peer's gossip. Cosigns only a head that is validly signed AND consistent with everything seen. */
  async onHead(h: STH): Promise<HeadResult> {
    const { logId, logPublicKey } = this.cfg;
    const sth: STH = { ...h, cosigs: [] };
    if (h.logId !== logId || !verifyLogSig(sth, logPublicKey)) return { status: "rejected", detail: "not a head signed by the pinned log key" };

    const prior = this.heads.get(sth.treeSize);
    if (prior && prior.rootHash !== sth.rootHash) return this.fork(prior, sth); // same size, two roots, both log-signed
    this.heads.set(sth.treeSize, prior ?? sth);

    const last = this.last;
    if (!last) return this.cosignHead(sth); // first sight: trust on first use
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

  private cosignHead(sth: STH): HeadResult {
    const ts = this.d.now().toISOString();
    this.last = sth;
    this.lastCosignAt = this.d.now().getTime();
    this.lastCosigned = { ...sth, cosigs: [cosign(sth, this.cfg.id, this.cfg.secretKey, ts)] };
    return { status: "cosigned", sth: this.lastCosigned };
  }

  /** §8 Observations: more than one distinct sha256 for a release -> HASH_MISMATCH; a hash the log does not hold -> NOT_IN_LOG. */
  async observe(o: Observation): Promise<SplitViewAlert[]> {
    const rel = { app: o.app, version: o.version, platform: o.platform };
    const k = `${o.app}\0${o.version}\0${o.platform}`;
    const byHash = this.obs.get(k) ?? new Map<string, Observation>();
    this.obs.set(k, byHash);
    if (byHash.has(o.sha256)) return [];
    const others = [...byHash.values()];
    byHash.set(o.sha256, o);
    const raised = others.map((other) => this.alert("HASH_MISMATCH", rel, { hashes: [other.sha256, o.sha256], observationA: other, observationB: o }));
    try {
      if (!(await this.d.logHashes(o.app, o.version, o.platform)).includes(o.sha256)) raised.push(this.alert("NOT_IN_LOG", rel, { sha256: o.sha256, observation: o }));
    } catch { /* log unreachable: cannot say it is missing, so no alert (a later observation of the same hash is ignored; the client fails closed on its own) */ }
    return raised;
  }

  /** Alerts for a release. With `sha256` (what a client asks) only alerts that concern THAT binary come back, so one bad actor
   *  reporting a random hash cannot block every client of a release (docs/spec-amendments.md):
   *   - INCONSISTENT_STH: always (only the log's own signatures can cause it);
   *   - NOT_IN_LOG: only for the same hash;
   *   - HASH_MISMATCH: only when the log holds two or more of the conflicting hashes, including this one (a real equivocation). */
  async alerts(f: AlertFilter = {}): Promise<SplitViewAlert[]> {
    const m = this.all.filter((a) => a.app === ANY || ((!f.app || a.app === f.app) && (!f.version || a.version === f.version) && (!f.platform || a.platform === f.platform)));
    if (f.sha256 === undefined) return m;
    const out: SplitViewAlert[] = [];
    for (const a of m) {
      if (a.kind === "NOT_IN_LOG") { if (a.evidence.sha256 === f.sha256) out.push(a); }
      else if (a.kind === "HASH_MISMATCH") {
        const hashes = a.evidence.hashes as string[];
        let logged = hashes;
        try { const l = await this.d.logHashes(a.app, a.version, a.platform); logged = hashes.filter((x) => l.includes(x)); } catch { /* unreachable: fail closed, treat all as logged */ }
        if (logged.length >= 2 && logged.includes(f.sha256)) out.push(a);
      } else out.push(a);
    }
    return out;
  }
}
