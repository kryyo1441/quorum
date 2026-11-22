import { Hono } from "hono";
import { CompactTree, consistencyPath, inclusionPath, leafHashOfEntry, verifyEntry } from "@uw/log-core";
import { ReleaseEntry } from "@uw/shared";
import { signHead, type LogIdentity } from "./log.js";
import type { Leaf, LogStore } from "./store.js";

class Tampered extends Error {}

/** vendorKeys: keyId -> base64 public key. Only entries validly signed by a registered vendor key are appended.
 *  Single-writer: this process owns the tree (appends are serialised here and the in-memory tree must match the store). */
export function createApp(store: LogStore, id: LogIdentity, vendorKeys: Record<string, string>) {
  const app = new Hono();
  app.onError((e, c) => e instanceof Tampered ? c.json({ error: e.message }, 500) : c.json({ error: "internal" }, 500));

  /** Every read re-derives each leaf hash from its stored entry, so editing only the entry (or only the hash) in storage is detected, not served.
   *  ponytail: O(n) hashing per read; cache by idx once logs are large. */
  const leaves = async (): Promise<Leaf[]> => {
    const all = await store.all();
    for (const l of all) if (leafHashOfEntry(l.entry) !== l.leafHash) throw new Tampered(`storage tampered at leaf ${l.idx}: entry does not match its leaf hash`);
    return all;
  };

  // O(log n) append: incremental tree, built once from verified storage. Appends run one at a time so heads match their leaf's position.
  let tree: Promise<CompactTree> | undefined;
  let queue: Promise<unknown> = Promise.resolve();
  const serial = <T>(f: () => Promise<T>): Promise<T> => { const r = queue.then(() => f()); queue = r.catch(() => {}); return r; };

  app.get("/health", (c) => c.json({ ok: true }));
  app.get("/key", (c) => c.json({ logId: id.logId, publicKey: id.publicKey }));

  app.post("/entries", async (c) => {
    const p = ReleaseEntry.safeParse(await c.req.json().catch(() => null));
    if (!p.success) return c.json({ error: p.error.issues }, 400);
    const e = p.data, pub = Object.hasOwn(vendorKeys, e.vendorKeyId) ? vendorKeys[e.vendorKeyId] : undefined;
    // An unsigned or foreign entry must not be loggable: otherwise anyone could put an attacker's hash "in the log".
    if (!pub || !verifyEntry(e, pub)) return c.json({ error: "vendorSig does not verify under a registered vendor key" }, 403);
    return serial(async () => {
      tree ??= leaves().then((ls) => new CompactTree(ls.map((l) => l.leafHash)));
      const t = await tree, leafHash = leafHashOfEntry(e);
      const leaf = await store.append(e, leafHash);
      if (leaf.idx !== t.size) throw new Error(`store index ${leaf.idx} diverged from tree size ${t.size}: another writer?`);
      const path = t.append(leafHash);
      const sth = signHead(id, t.size, t.root());
      await store.saveSth(sth);
      return c.json({ ...leaf, sth, inclusion: { leafIndex: leaf.idx, treeSize: t.size, path } }, 201);
    });
  });
  app.get("/entries", async (c) => c.json(await leaves()));
  app.get("/entries/:idx", async (c) => {
    const l = (await leaves())[Number(c.req.param("idx"))];
    return l ? c.json(l) : c.json({ error: "not found" }, 404);
  });

  app.get("/sth", async (c) => { const h = await store.latestSth(); return h ? c.json(h) : c.json({ error: "no signed tree head yet" }, 404); });
  app.get("/sths", async (c) => c.json(await store.allSths()));
  app.get("/sth/:size", async (c) => { const h = await store.sthAt(Number(c.req.param("size"))); return h ? c.json(h) : c.json({ error: "not found" }, 404); });

  /** Inclusion proof, by leaf hash (what a client knows) or by index, at `treeSize` (default: latest head). */
  const proof = async (c: any, find: (hashes: string[]) => number) => {
    const hashes = (await leaves()).map((l) => l.leafHash);
    const size = c.req.query("treeSize") === undefined ? (await store.latestSth())?.treeSize ?? 0 : Number(c.req.query("treeSize"));
    if (!Number.isInteger(size) || size < 1 || size > hashes.length) return c.json({ error: "bad treeSize" }, 400);
    const idx = find(hashes.slice(0, size));
    if (!Number.isInteger(idx)) return c.json({ error: "bad index" }, 400);
    if (idx < 0 || idx >= size) return c.json({ error: "not in tree at that size" }, 404);
    return c.json({ leafIndex: idx, treeSize: size, path: inclusionPath(hashes.slice(0, size), idx), leafHash: hashes[idx] });
  };
  app.get("/proof", (c) => proof(c, (h) => h.indexOf(c.req.query("leafHash") ?? "")));
  app.get("/entries/:idx/proof", (c) => proof(c, () => Number(c.req.param("idx"))));

  app.get("/consistency", async (c) => {
    const hashes = (await leaves()).map((l) => l.leafHash);
    const from = Number(c.req.query("from")), to = Number(c.req.query("to") ?? hashes.length);
    if (!(Number.isInteger(from) && Number.isInteger(to) && from >= 1 && from <= to && to <= hashes.length)) return c.json({ error: "need 1 <= from <= to <= tree size" }, 400);
    return c.json({ fromSize: from, toSize: to, path: consistencyPath(hashes.slice(0, to), from) });
  });
  return app;
}
