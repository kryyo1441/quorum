import { Hono } from "hono";
import { consistencyPath, inclusionPath, leafHashOfEntry } from "@uw/log-core";
import { ReleaseEntry } from "@uw/shared";
import { headFor, type LogIdentity } from "./log.js";
import type { LogStore } from "./store.js";

export function createApp(store: LogStore, id: LogIdentity) {
  const app = new Hono();
  app.get("/health", (c) => c.json({ ok: true }));
  app.get("/key", (c) => c.json({ logId: id.logId, publicKey: id.publicKey }));

  app.post("/entries", async (c) => {
    const p = ReleaseEntry.safeParse(await c.req.json().catch(() => null));
    if (!p.success) return c.json({ error: p.error.issues }, 400);
    // ponytail: vendorSig is not verified here; the log accepts any well-formed entry (CT-style) and
    // clients/monitor judge it. Add vendor-key checking if the log should reject unsigned entries.
    const leaf = await store.append(p.data, leafHashOfEntry(p.data));
    // One signed head per growth. Computed from this leaf's own position, so concurrent appends cannot skew it.
    await store.saveSth(headFor(id, (await store.all()).map((l) => l.leafHash), leaf.idx + 1));
    return c.json(leaf, 201);
  });
  app.get("/entries", async (c) => c.json(await store.all()));
  app.get("/entries/:idx", async (c) => {
    const l = (await store.all())[Number(c.req.param("idx"))];
    return l ? c.json(l) : c.json({ error: "not found" }, 404);
  });

  app.get("/sth", async (c) => { const h = await store.latestSth(); return h ? c.json(h) : c.json({ error: "no signed tree head yet" }, 404); });
  app.get("/sth/:size", async (c) => { const h = await store.sthAt(Number(c.req.param("size"))); return h ? c.json(h) : c.json({ error: "not found" }, 404); });

  /** Inclusion proof, by leaf hash (what a client knows) or by index, at `treeSize` (default: latest head). */
  const proof = async (c: any, find: (hashes: string[]) => number) => {
    const hashes = (await store.all()).map((l) => l.leafHash);
    const size = c.req.query("treeSize") === undefined ? (await store.latestSth())?.treeSize ?? 0 : Number(c.req.query("treeSize"));
    if (!Number.isInteger(size) || size < 1 || size > hashes.length) return c.json({ error: "bad treeSize" }, 400);
    const idx = find(hashes.slice(0, size));
    if (idx < 0 || idx >= size) return c.json({ error: "not in tree at that size" }, 404);
    return c.json({ leafIndex: idx, treeSize: size, path: inclusionPath(hashes.slice(0, size), idx), leafHash: hashes[idx] });
  };
  app.get("/proof", (c) => proof(c, (h) => h.indexOf(c.req.query("leafHash") ?? "")));
  app.get("/entries/:idx/proof", (c) => proof(c, () => Number(c.req.param("idx"))));

  app.get("/consistency", async (c) => {
    const hashes = (await store.all()).map((l) => l.leafHash);
    const from = Number(c.req.query("from")), to = Number(c.req.query("to") ?? hashes.length);
    if (!(Number.isInteger(from) && Number.isInteger(to) && from >= 1 && from <= to && to <= hashes.length)) return c.json({ error: "need 1 <= from <= to <= tree size" }, 400);
    return c.json({ fromSize: from, toSize: to, path: consistencyPath(hashes.slice(0, to), from) });
  });
  return app;
}
