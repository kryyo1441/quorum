// An in-process copy of the whole system (log, update server, 3 witnesses, monitor) on a controllable clock, routed by host name instead of ports.
// Real services, real crypto, no mocks: this is what the adversarial suite (§10) and its tests run against.
import { generateKeypair } from "@uw/log-core";
import { Monitor, WitnessCore } from "@uw/witness-core";
import { STH } from "@uw/shared";
import type { Hono } from "hono";
import { createApp as logApp } from "../../services/log-server/src/app.js";
import { newIdentity } from "../../services/log-server/src/log.js";
import { memoryStore } from "../../services/log-server/src/store.js";
import { createApp as monitorApp } from "../../services/monitor/src/app.js";
import { createApp as updateApp } from "../../services/update-server/src/app.js";
import { createApp as witnessApp } from "../../services/witness/src/app.js";
import { netDeps, runner } from "../../services/witness/src/runner.js";
import type { Env } from "./fleet.js";

export function createWorld(o: { witnesses?: number; threshold?: number } = {}) {
  const clock = { t: Date.parse("2026-06-01T12:00:00.000Z") }, nW = o.witnesses ?? 3, TOKEN = "monitor-token";
  const logId = newIdentity("uw-test-log"), vendor = generateKeypair(), approver = generateKeypair(), wkeys = Array.from({ length: nW }, () => generateKeypair());
  const witnessKeys = Object.fromEntries(wkeys.map((k, i) => [`w${i + 1}`, k.publicKey]));
  const hosts = new Map<string, Hono>(), down = new Set<string>();
  const fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const u = new URL(String(input));
    if (down.has(u.host)) throw new TypeError(`fetch failed: ${u.host} unreachable`);
    const app = hosts.get(u.host);
    if (!app) throw new TypeError(`fetch failed: unknown host ${u.host}`);
    return app.request(u.pathname + u.search, init);
  }) as typeof globalThis.fetch;
  const now = () => clock.t;

  const store = memoryStore();
  hosts.set("log", logApp(store, logId, { demo: vendor.publicKey }, witnessKeys, now, approver.publicKey));
  hosts.set("update", updateApp());
  const urls = wkeys.map((_, i) => `http://w${i + 1}`);
  const witnesses = wkeys.map((k, i) => {
    const net = { logUrl: "http://log", peers: urls.filter((_, j) => j !== i), fetch, now: () => new Date(clock.t) };
    const core: WitnessCore = new WitnessCore({ id: `w${i + 1}`, secretKey: k.secretKey, logId: logId.logId, logPublicKey: logId.publicKey, heartbeatMs: 10_000 }, netDeps(net, () => core.head()));
    const run = runner(core, net);
    hosts.set(`w${i + 1}`, witnessApp(`w${i + 1}`, core, run.onHead));
    return { id: `w${i + 1}`, url: urls[i], host: `w${i + 1}`, secretKey: k.secretKey, publicKey: k.publicKey, core, run };
  });
  const monitor = new Monitor({ logId: logId.logId, logPublicKey: logId.publicKey, vendorPublicKeys: { demo: vendor.publicKey } }, {
    entries: async () => (await fetch("http://log/entries")).json() as never,
    head: async () => STH.parse(await (await fetch("http://log/sth")).json()),
    consistency: async (a, b) => ((await (await fetch(`http://log/consistency?from=${a}&to=${b}`)).json()) as { path: string[] }).path,
    now: () => new Date(clock.t),
  });
  hosts.set("monitor", monitorApp(monitor, TOKEN));

  /** One cycle of every background loop: each witness polls the log + gossips, then the monitor polls. */
  const settle = async (rounds = 2) => { for (let i = 0; i < rounds; i++) { for (const w of witnesses) await w.run.tick(true); await monitor.poll().catch(() => {}); } };
  const env: Env = {
    updateUrl: "http://update", logUrl: "http://log", monitor: { url: "http://monitor", token: TOKEN },
    vendor: { keyId: "demo", secretKey: vendor.secretKey }, approver: { secretKey: approver.secretKey },
    verify: { logUrl: "http://log", threshold: o.threshold ?? 2, maxAgeMs: 5 * 60_000, logPublicKey: logId.publicKey, vendorPublicKeys: { demo: vendor.publicKey }, approverPublicKey: approver.publicKey,
      witnesses: witnesses.map((w) => ({ id: w.id, url: w.url, publicKey: w.publicKey })) },
    fetch, now, settle,
  };
  /** A second log that holds the SAME log key: the attacker is the log operator. Not a route of the real log-server. */
  const forkLog = (host = "evil") => { const s = memoryStore(); hosts.set(host, logApp(s, logId, { demo: vendor.publicKey }, witnessKeys, now)); return { host, url: `http://${host}`, store: s }; };
  return { clock, env, fetch, store, logId, vendor, approver, witnesses, monitor, settle, down, forkLog, hosts };
}
export type World = ReturnType<typeof createWorld>;
