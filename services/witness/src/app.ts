import { Hono } from "hono";
import { cors } from "hono/cors";
import { Observation, STH } from "@uw/shared";
import type { HeadResult, WitnessCore } from "@uw/witness-core";

/** `onHead` is the one path every head takes (log poll or gossip): core check, then (if it cosigned) submit the cosig to the log. */
export function createApp(id: string, core: WitnessCore, onHead: (h: STH) => Promise<HeadResult>) {
  const app = new Hono();
  app.use(cors()); // /verify runs the client checks in the browser and reads /alerts
  app.get("/health", (c) => c.json({ id, ok: true }));
  app.get("/sth", (c) => { const h = core.head(); return h ? c.json(h) : c.json({ error: "no cosigned head yet" }, 404); });
  app.post("/observations", async (c) => {
    const p = Observation.safeParse(await c.req.json().catch(() => null));
    if (!p.success) return c.json({ error: p.error.issues }, 400);
    return c.json({ raised: await core.observe(p.data) });
  });
  app.get("/alerts", async (c) => { const { app: a, version, platform, sha256 } = c.req.query(); return c.json(await core.alerts({ app: a, version, platform, sha256 })); });
  /** Peers push their latest head. Anything not validly signed by the pinned log key is rejected by the core. */
  app.post("/gossip", async (c) => {
    const p = STH.safeParse(await c.req.json().catch(() => null));
    if (!p.success) return c.json({ error: p.error.issues }, 400);
    const r = await onHead(p.data);
    return c.json({ status: r.status });
  });
  return app;
}
