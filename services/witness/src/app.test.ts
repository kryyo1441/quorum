import { CompactTree, consistencyPath, generateKeypair, leafHashOfEntry, signEntry, signSTH, verifyCosig } from "@uw/log-core";
import { WitnessCore } from "@uw/witness-core";
import { expect, test } from "vitest";
import { createApp } from "./app.js";
import { netDeps, runner } from "./runner.js";

const log = generateKeypair(), wk = generateKeypair(), LOG = "log-1";
const vendor = generateKeypair(), G = "a".repeat(64), E = "b".repeat(64);
// a log whose entries really hash to the heads it signs (the witness authenticates the listing against its cosigned head)
const entries = Array.from({ length: 4 }, (_, i) => signEntry({ app: "a", version: i === 0 ? "1.0.0" : `1.0.${i}`, platform: "win-x64", sha256: i === 0 ? G : String(i).repeat(64), size: 1, url: "u", publishedAt: "2026-01-01T00:00:00.000Z", vendorKeyId: "k" }, vendor.secretKey));
const hs = entries.map(leafHashOfEntry);
const headOf = (n: number) => signSTH({ logId: LOG, treeSize: n, rootHash: new CompactTree(hs.slice(0, n)).root(), timestamp: "2026-06-01T00:00:00.000Z" }, log.secretKey);
const cfg = { id: "w1", secretKey: wk.secretKey, logId: LOG, logPublicKey: log.publicKey, heartbeatMs: 60_000 };
const obs = (sha256: string, who: string) => ({ app: "a", version: "1.0.0", platform: "win-x64", sha256, sthRoot: "", sthSize: 0, clientPseudonym: who, observedAt: "x" });
const post = (app: ReturnType<typeof createApp>, path: string, b: unknown) => app.request(path, { method: "POST", body: JSON.stringify(b) });

/** A fake log: serves /sth, /consistency, /entries and records cosigs posted to it. */
function fakeLog(size: number) {
  const posted: any[] = [];
  const f = (async (url: string, init?: RequestInit) => {
    const u = new URL(url);
    if (u.pathname === "/sth") return Response.json(headOf(size));
    if (u.pathname === "/consistency") return Response.json({ path: consistencyPath(hs.slice(0, Number(u.searchParams.get("to"))), Number(u.searchParams.get("from"))) });
    if (u.pathname === "/entries") return Response.json(entries.slice(0, size).map((entry, idx) => ({ idx, entry, leafHash: hs[idx] })));
    if (u.pathname.endsWith("/cosigs")) { posted.push(JSON.parse(String(init?.body))); return Response.json({ ok: true }, { status: 201 }); }
    return new Response("nope", { status: 404 });
  }) as unknown as typeof fetch;
  return { f, posted };
}
function witness(size = 3) {
  const l = fakeLog(size), net = { logUrl: "http://log", peers: [], fetch: l.f };
  const core: WitnessCore = new WitnessCore(cfg, netDeps(net, () => core.head())), r = runner(core, net);
  return { core, r, l, app: createApp("w1", core, r.onHead) };
}

test("a poll cosigns the log's head, posts the cosig to the log, and serves it at /sth", async () => {
  const { r, l, app } = witness(3);
  await r.tick(false);
  expect(l.posted).toHaveLength(1);
  expect(verifyCosig(headOf(3), l.posted[0], wk.publicKey)).toBe(true);
  expect((await (await app.request("/sth")).json()).cosigs).toHaveLength(1);
});
test("a down log is survived: no cosign, no crash", async () => {
  const core = new WitnessCore(cfg, netDeps({ logUrl: "http://log", peers: [], fetch: (async () => { throw new Error("down"); }) as unknown as typeof fetch }, () => undefined));
  const r = runner(core, { logUrl: "http://log", peers: [], fetch: (async () => { throw new Error("down"); }) as unknown as typeof fetch });
  await r.tick();
  expect(core.head()).toBeUndefined();
});
test("gossip: a forked head from a peer raises INCONSISTENT_STH; garbage is rejected", async () => {
  const { r, app } = witness(3);
  await r.tick(false);
  const evil = signSTH({ logId: LOG, treeSize: 3, rootHash: "f".repeat(64), timestamp: "2026-06-01T00:00:00.000Z" }, log.secretKey); // log-key holder forks
  expect((await (await post(app, "/gossip", evil)).json()).status).toBe("inconsistent");
  expect((await (await app.request("/alerts?app=any")).json())[0].kind).toBe("INCONSISTENT_STH");
  expect((await (await post(app, "/gossip", { ...headOf(3), logSig: "x" })).json()).status).toBe("rejected");
  expect((await post(app, "/gossip", { nope: 1 })).status).toBe(400);
});
test("observations: c7's tampered hash is flagged; clients with the logged hash are not blocked", async () => {
  const { app, r: run } = witness();
  await run.tick(false);                                  // the witness cosigns the head first: only then can it authenticate the log's listing
  await post(app, "/observations", obs(G, "c1"));
  const r = await (await post(app, "/observations", obs(E, "c7"))).json();
  expect(r.raised.map((a: any) => a.kind).sort()).toEqual(["HASH_MISMATCH", "NOT_IN_LOG"]);
  expect(await (await app.request("/alerts?app=a&version=1.0.0&platform=win-x64&sha256=" + G + "")).json()).toEqual([]);
  expect((await post(app, "/observations", { nope: 1 })).status).toBe(400);
});

test("admin reset needs the token and is off without one", async () => {
  const { core, r } = witness();
  const on = createApp("w1", core, r.onHead, "tok"), off = createApp("w1", core, r.onHead);
  const go = (a: typeof on, auth?: string) => a.request("/admin/reset", { method: "POST", headers: auth ? { authorization: auth } : {} });
  expect((await go(on)).status).toBe(401);
  expect((await go(on, "Bearer nope")).status).toBe(401);
  expect((await go(off, "Bearer tok")).status).toBe(401);
  await post(on, "/observations", obs(E, "c7")); await post(on, "/observations", obs(G, "c1"));
  expect((await go(on, "Bearer tok")).status).toBe(200);
  expect(await (await on.request("/alerts?app=a")).json()).toEqual([]);
});

test("a log that lists fewer entries than the head it signed cannot make a conflict disappear: the witness fails closed", async () => {
  const l = fakeLog(3), lying = ((u: string, i?: RequestInit) => new URL(u).pathname === "/entries" ? Promise.resolve(Response.json(entries.slice(0, 1).map((entry, idx) => ({ idx, entry, leafHash: hs[idx] })))) : l.f(u, i)) as unknown as typeof fetch;
  const net = { logUrl: "http://log", peers: [], fetch: lying }, core: WitnessCore = new WitnessCore(cfg, netDeps(net, () => core.head())), r = runner(core, net), app = createApp("w1", core, r.onHead);
  await r.tick(false);
  await post(app, "/observations", obs(G, "c1")); await post(app, "/observations", obs(E, "c7"));
  const a = await (await app.request("/alerts?app=a&version=1.0.0&platform=win-x64&sha256=" + G)).json();
  expect(a.map((x: any) => x.kind)).toContain("HASH_MISMATCH"); // listing rejected -> everything is treated as logged -> blocked
});
test("public POST bodies are size-limited", async () => {
  const { app } = witness();
  expect((await app.request("/observations", { method: "POST", body: "x".repeat(70_000) })).status).toBe(413);
});
