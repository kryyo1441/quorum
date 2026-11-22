import { Hono } from "hono";
import { ReleaseEntry } from "@uw/shared";
import { NotImplemented, type LogCore } from "./core.js";
import type { LogStore } from "./store.js";

export function createApp(store: LogStore, core: LogCore) {
  const app = new Hono();
  // Proof/STH routes surface core's NotImplemented as 501 instead of a 500.
  app.onError((e, c) => e instanceof NotImplemented ? c.json({ error: e.message }, 501) : c.json({ error: "internal" }, 500));

  app.get("/health", (c) => c.json({ ok: true }));

  app.post("/entries", async (c) => {
    const p = ReleaseEntry.safeParse(await c.req.json().catch(() => null));
    if (!p.success) return c.json({ error: p.error.issues }, 400);
    // ponytail: vendorSig is not verified here; the log accepts any well-formed entry (CT-style) and
    // clients/monitor judge it. Add vendor-key checking if the log should reject unsigned entries.
    return c.json(await store.append(p.data, core.leafHash(p.data)), 201);
  });
  app.get("/entries", async (c) => c.json(await store.all()));
  app.get("/entries/:idx", async (c) => {
    const l = (await store.all())[Number(c.req.param("idx"))];
    return l ? c.json(l) : c.json({ error: "not found" }, 404);
  });
  app.get("/entries/:idx/proof", async (c) => {
    const hashes = (await store.all()).map((l) => l.leafHash);
    const idx = Number(c.req.param("idx"));
    if (!(idx >= 0 && idx < hashes.length)) return c.json({ error: "not found" }, 404);
    return c.json(core.inclusionProof(hashes, idx));
  });
  app.get("/sth", async (c) => {
    const h = core.sth((await store.all()).map((l) => l.leafHash));
    return h ? c.json(h) : c.json({ error: "no signed tree head yet" }, 404);
  });
  app.get("/consistency", async (c) => {
    const hashes = (await store.all()).map((l) => l.leafHash);
    return c.json(core.consistencyProof(hashes, Number(c.req.query("from")), Number(c.req.query("to") ?? hashes.length)));
  });
  return app;
}
