import { Hono } from "hono";
import { Observation } from "@uw/shared";
import type { WitnessCore } from "./core.js";

export function createApp(id: string, core: WitnessCore) {
  const app = new Hono();
  app.get("/health", (c) => c.json({ id, ok: true }));
  app.get("/sth", (c) => { const h = core.head(); return h ? c.json(h) : c.json({ error: "no cosigned head yet" }, 404); });
  app.post("/observations", async (c) => {
    const p = Observation.safeParse(await c.req.json().catch(() => null));
    if (!p.success) return c.json({ error: p.error.issues }, 400);
    return c.json({ raised: core.observe(p.data) });
  });
  app.get("/alerts", (c) => c.json(core.alerts(c.req.query())));
  // ponytail: gossip needs signature + consistency verification from witness-core, so honestly 501.
  app.post("/gossip", (c) => c.json({ error: "not implemented: needs witness-core" }, 501));
  return app;
}
