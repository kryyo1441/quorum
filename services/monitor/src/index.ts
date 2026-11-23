import { serve } from "@hono/node-server";
import { devSecret, publicKeyOf } from "@uw/log-core";
import { Monitor } from "@uw/witness-core";
import { STH } from "@uw/shared";
import { createApp } from "./app.js";

const env = process.env, dev = env.DEV === "1", logUrl = env.LOG_URL ?? "http://localhost:4000";
// Required unless DEV=1 (public demo keys / token): without a pinned log key and a private token the monitor would prove nothing.
if (!dev && !(env.LOG_PUBLIC_KEY && env.VENDOR_PUBLIC_KEYS && env.MONITOR_TOKEN)) throw new Error("LOG_PUBLIC_KEY, VENDOR_PUBLIC_KEYS and MONITOR_TOKEN are required (DEV=1 only for demos)");
const j = async (p: string) => { const r = await fetch(`${logUrl}${p}`, { signal: AbortSignal.timeout(4000) }); if (!r.ok) throw new Error(`${p} -> ${r.status}`); return r.json() as Promise<any>; };
const m = new Monitor(
  { logId: env.LOG_ID ?? "uw-dev-log", logPublicKey: env.LOG_PUBLIC_KEY ?? publicKeyOf(devSecret("log")), vendorPublicKeys: env.VENDOR_PUBLIC_KEYS ? JSON.parse(env.VENDOR_PUBLIC_KEYS) : { demo: publicKeyOf(devSecret("vendor")) } },
  { entries: () => j("/entries"), head: async () => STH.parse(await j("/sth")), consistency: async (a, b) => (await j(`/consistency?from=${a}&to=${b}`)).path, now: () => new Date() },
);
let busy = false;
setInterval(async () => { if (busy) return; busy = true; try { for (const a of await m.poll()) console.warn(`ALERT ${a.kind} ${a.app} ${a.version} ${a.platform}`); } catch (e) { console.warn("poll failed:", e instanceof Error ? e.message : e); } finally { busy = false; } }, Number(env.POLL_MS ?? 2000));
serve({ fetch: createApp(m, env.MONITOR_TOKEN ?? "dev-monitor-token").fetch, port: Number(env.PORT ?? 4300) });
