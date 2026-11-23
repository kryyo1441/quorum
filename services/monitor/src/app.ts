import { Hono } from "hono";
import { cors } from "hono/cors";
import { timingSafeEqual } from "node:crypto";
import { z } from "zod";
import type { Monitor } from "@uw/witness-core";

const Approved = z.object({ app: z.string(), version: z.string(), platform: z.string(), sha256: z.string().regex(/^[0-9a-f]{64}$/) }).strict();
const same = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

/** The approved list is writable only with `token`, a credential SEPARATE from the vendor release key: an attacker who steals the
 *  release key and logs a malicious release (scenario 4) still cannot add it to the approved list. */
export function createApp(m: Monitor, token: string) {
  const app = new Hono();
  app.use(cors());
  app.get("/health", (c) => c.json({ ok: true }));
  app.get("/alerts", (c) => c.json(m.alerts));
  app.post("/approved", async (c) => {
    if (!same(c.req.header("authorization") ?? "", `Bearer ${token}`)) return c.json({ error: "unauthorized" }, 401);
    const p = Approved.safeParse(await c.req.json().catch(() => null));
    if (!p.success) return c.json({ error: p.error.issues }, 400);
    m.approve(p.data);
    return c.json({ ok: true }, 201);
  });
  return app;
}
