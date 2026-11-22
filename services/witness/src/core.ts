import type { Observation, SplitViewAlert, STH } from "@uw/shared";

/** The seam between this service (Sonnet) and packages/witness-core (Opus, SPEC §8).
 *  When witness-core lands, implement this interface over it and pass it to createApp. */
export interface WitnessCore {
  observe(o: Observation): SplitViewAlert[];
  alerts(f?: { app?: string; version?: string; platform?: string }): SplitViewAlert[];
  head(): STH | undefined;
}

/** STUB: observation indexing only (§8 "Observations"), in memory.
 *  NOT implemented, belongs to witness-core: STH consistency checking, cosigning,
 *  gossip conflict detection, NOT_IN_LOG lookups. head() is always undefined (nothing is cosigned). */
export function stubCore(witnessId: string): WitnessCore {
  const seen = new Map<string, Map<string, Observation>>(); // app/version/platform -> sha256 -> first observation
  const alerts: SplitViewAlert[] = [];
  return {
    observe(o) {
      const k = `${o.app}/${o.version}/${o.platform}`;
      const byHash = seen.get(k) ?? new Map<string, Observation>();
      seen.set(k, byHash);
      if (byHash.has(o.sha256)) return [];
      const others = [...byHash.values()];
      byHash.set(o.sha256, o);
      const raised = others.map<SplitViewAlert>((other) => ({
        kind: "HASH_MISMATCH", app: o.app, version: o.version, platform: o.platform,
        evidence: { observationA: other, observationB: o }, // ponytail: unsigned evidence, witness-core signs it
        raisedBy: witnessId, raisedAt: new Date().toISOString(),
      }));
      alerts.push(...raised);
      return raised;
    },
    alerts: (f = {}) => alerts.filter((a) => (!f.app || a.app === f.app) && (!f.version || a.version === f.version) && (!f.platform || a.platform === f.platform)),
    head: () => undefined,
  };
}
