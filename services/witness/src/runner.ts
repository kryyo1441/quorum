import { type HeadResult, type WitnessCore, type WitnessDeps } from "@uw/witness-core";
import { STH } from "@uw/shared";
import { leafHashOfEntry, rootHash } from "@uw/log-core";

export type RunnerCfg = { logUrl: string; peers: string[]; fetch: typeof fetch; now?: () => Date };
const j = async (r: Response) => { if (!r.ok) throw new Error(`${r.url} -> ${r.status}`); return r.json() as Promise<any>; };
const get = (c: RunnerCfg, u: string, init?: RequestInit) => c.fetch(u, { ...init, signal: AbortSignal.timeout(4000) });

/** What the core needs from the network: consistency proofs and the log's hashes for a release. */
export function netDeps(c: RunnerCfg, verifiedHead: () => { treeSize: number; rootHash: string } | undefined): WitnessDeps {
  let cache: { at: number; entries: any[] } | undefined;
  return {
    now: c.now ?? (() => new Date()),
    consistency: async (from, to) => (await j(await get(c, `${c.logUrl}/consistency?from=${from}&to=${to}`))).path,
    // ponytail: whole-log fetch cached 1s; a real deployment queries by release.
    // The listing is AUTHENTICATED against the head this witness verified and cosigned: all treeSize entries, and their recomputed root must equal the head's root.
    // A log cannot hide a logged release (or invent one) in what it lists without breaking that, so a bad listing throws and callers fail closed.
    logHashes: async (app, version, platform) => {
      const head = verifiedHead();
      if (!head) throw new Error("no verified head yet: cannot authenticate the log's listing");
      if (!cache || Date.now() - cache.at > 1000) cache = { at: Date.now(), entries: await j(await get(c, `${c.logUrl}/entries`)) };
      const listing = cache.entries.slice(0, head.treeSize);
      if (listing.length < head.treeSize || rootHash(listing.map((l) => leafHashOfEntry(l.entry))) !== head.rootHash) throw new Error("the log's entry listing does not match the head it signed");
      return listing.filter((l) => l.entry.app === app && l.entry.version === version && l.entry.platform === platform).map((l) => l.entry.sha256);
    },
  };
}

/** Network side of a witness: polls the log, hands every head to the core, posts new cosigs back to the log, gossips the latest head to peers. */
export function runner(core: WitnessCore, c: RunnerCfg) {
  const onHead = async (h: STH): Promise<HeadResult> => {
    const r = await core.onHead(h);
    if (r.status === "cosigned") await get(c, `${c.logUrl}/sth/${r.sth.treeSize}/cosigs`, { method: "POST", body: JSON.stringify(r.sth.cosigs[0]) }).catch(() => {}); // log down: re-sent on the next heartbeat
    return r;
  };
  return {
    onHead,
    /** One cycle. Never throws; a down log or peer is simply retried next time. */
    async tick(gossip = true) {
      try { await onHead(STH.parse(await j(await get(c, `${c.logUrl}/sth`)))); } catch { /* log unreachable or malformed: nothing to cosign */ }
      const mine = core.head();
      if (gossip && mine) await Promise.allSettled(c.peers.map((p) => get(c, `${p}/gossip`, { method: "POST", body: JSON.stringify(mine) })));
    },
  };
}
