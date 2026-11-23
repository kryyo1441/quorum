// HTTP face of the demo for the dashboard: drives the LIVE stack (fleet, attack 1) and runs the hermetic adversarial suite.
// It holds the vendor secret, like a vendor's release machine would, so the browser never sees it.
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { streamSSE } from "hono/streaming";
import { envFromProcess } from "./env.js";
import { liveAttacks } from "./attacks.js";
import { APP, PLATFORM, attack1, clientIds, publish, runClient } from "./fleet.js";
import { SCENARIOS, metrics, runScenario } from "./scenarios.js";

const env = envFromProcess();
const live = liveAttacks(env, { logSecret: process.env.LOG_SECRET_KEY, logId: process.env.LOG_ID, databaseUrl: process.env.DATABASE_URL, adminToken: process.env.ADMIN_TOKEN ?? (process.env.DEV === "1" ? "dev-admin-token" : undefined) });
const fleetEnv = { ...env, logFor: live.logFor }; // attack 5: one client is shown a forked log
const app = new Hono();
app.use(cors());
app.onError((e, c) => c.json({ error: e.message }, 502)); // a stack that is down is reported, never faked

/** Publish once per update-server lifetime: the fleet needs a release that is logged AND cosigned. */
let publishing: Promise<unknown> | undefined;
const ensurePublished = async () => {
  if ((await env.fetch(`${env.updateUrl}/latest/${APP}/${PLATFORM}`)).ok) return;
  publishing ??= publish(env).finally(() => { publishing = undefined; });
  await publishing;
};

app.get("/health", (c) => c.json({ ok: true }));
app.post("/publish", async (c) => c.json(await publish(env)));
app.post("/reset", async (c) => { await live.reset(); return c.json({ ok: true }); });
app.get("/attacks/state", (c) => c.json(live.state()));
// attacks on the live stack (SPEC §10 #4, #5, #9); #1 is /attack1
app.post("/attacks/fork", async (c) => { await live.fork((await c.req.json<{ clientId: string }>()).clientId); return c.json({ ok: true }); });
app.post("/attacks/stolen-key", async (c) => { await live.stolenKey(); return c.json({ ok: true }); });
app.post("/attacks/tamper", async (c) => { await live.tamper(); return c.json({ ok: true }); });
app.post("/attack1", async (c) => { const { clientId } = await c.req.json<{ clientId: string }>(); await attack1(env, clientId); return c.json({ ok: true }); });

/** Server-sent events: one `result` event per client as it finishes (clients run concurrently). */
app.get("/fleet/stream", (c) => {
  const n = Math.min(Math.max(Number(c.req.query("n") ?? 12) || 12, 1), 50);
  return streamSSE(c, async (s) => {
    await ensurePublished();
    await s.writeSSE({ event: "start", data: JSON.stringify({ clients: clientIds(n) }) });
    await Promise.all(clientIds(n).map(async (id) => {
      const r = await runClient(fleetEnv, id).catch((e) => ({ id, state: "blocked" as const, reason: "NOT_IN_LOG" as const, detail: String(e), checks: [], ms: 0, hashMs: 0, networkMs: 0, bytes: 0, sha256: "" }));
      await s.writeSSE({ event: "result", data: JSON.stringify(r) });
    }));
    await s.writeSSE({ event: "done", data: "{}" });
  });
});

app.get("/scenarios", (c) => c.json(SCENARIOS.map(({ n, name, attack, expected }) => ({ n, name, attack, expected }))));
app.post("/scenarios/:n/run", async (c) => c.json(await runScenario(Number(c.req.param("n")))));
app.get("/metrics", async (c) => c.json(await metrics()));

serve({ fetch: app.fetch, port: Number(process.env.PORT ?? 4200) });
console.log(`demo server on :${process.env.PORT ?? 4200}`);
