import { serve } from "@hono/node-server";
import { devSecret, publicKeyOf } from "@uw/log-core";
import { WitnessCore } from "@uw/witness-core";
import { createApp } from "./app.js";
import { netDeps, runner } from "./runner.js";
import { pgState } from "./state.js";

const env = process.env, dev = env.DEV === "1", id = env.WITNESS_ID ?? "w1";
// Keys: the log key is PINNED (never fetched from the log we are witnessing). DEV=1 uses the PUBLIC dev keys, demos only.
if ((!env.LOG_PUBLIC_KEY || !env.WITNESS_SECRET_KEY) && !dev) throw new Error("LOG_PUBLIC_KEY and WITNESS_SECRET_KEY are required (set DEV=1 only for demos: public keys)");
const net = { logUrl: env.LOG_URL ?? "http://localhost:4000", peers: (env.PEERS ?? "").split(",").filter(Boolean), fetch };
const core = new WitnessCore(
  { id, secretKey: env.WITNESS_SECRET_KEY ?? devSecret(`witness-${id}`), logId: env.LOG_ID ?? "uw-dev-log", logPublicKey: env.LOG_PUBLIC_KEY ?? publicKeyOf(devSecret("log")), heartbeatMs: Number(env.HEARTBEAT_MS ?? 30_000) },
  netDeps(net),
);
// A restart must not make the witness trust the next head blindly again: with DATABASE_URL its state lives in its own Postgres schema.
if (env.DATABASE_URL) {
  const st = await pgState(env.DATABASE_URL, id), snap = await st.load();
  if (snap) { core.restore(snap); console.log(`restored: head of ${snap.last?.treeSize ?? 0} leaves, ${snap.alerts.length} alerts`); }
  core.onChange = () => void st.save(core.snapshot());
} else console.warn("DATABASE_URL not set: witness state is in memory, so a restart trusts the next head blindly");
const r = runner(core, net);
setInterval(() => void r.tick(), Number(env.POLL_MS ?? 2000)); // gossip rides the poll: ponytail: SPEC says every 10s, 2s is cheaper than a second timer
serve({ fetch: createApp(id, core, r.onHead, env.ADMIN_TOKEN ?? (dev ? "dev-admin-token" : undefined)).fetch, port: Number(env.PORT ?? 4101) });
