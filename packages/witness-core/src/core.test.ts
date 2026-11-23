import { CompactTree, consistencyPath, generateKeypair, hashLeaf, signSTH, verifyCosig } from "@uw/log-core";
import { expect, test } from "vitest";
import { WitnessCore, type WitnessDeps } from "./core.js";

const log = generateKeypair(), wit = generateKeypair(), LOG = "log-1";
const leaves = (n: number, tag = "a") => Array.from({ length: n }, (_, i) => hashLeaf(new TextEncoder().encode(`${tag}${i}`)));
const head = (ls: string[], t = 1000, key = log.secretKey) => { const tr = new CompactTree(ls); return signSTH({ logId: LOG, treeSize: ls.length, rootHash: tr.root(), timestamp: new Date(t).toISOString() }, key); };
function mk(real: string[], now = { t: 5000 }, logged: string[] = [G]) {
  const d: WitnessDeps = {
    consistency: async (f, t) => { if (t > real.length) throw new Error("log has no such size"); return consistencyPath(real.slice(0, t), f); },
    logHashes: async () => logged, now: () => new Date(now.t),
  };
  return { w: new WitnessCore({ id: "w1", secretKey: wit.secretKey, logId: LOG, logPublicKey: log.publicKey, heartbeatMs: 1000 }, d), now };
}
const H = (c: string) => c.repeat(64).slice(0, 64), G = H("a"), E = H("b"), H1 = H("c"), H2 = H("d");
const obs = (sha256: string, who = "c") => ({ app: "a", version: "1.0.0", platform: "win-x64", sha256, sthRoot: "", sthSize: 0, clientPseudonym: who, observedAt: "x" });

test("first head is cosigned with a cosig that verifies; a head that grows consistently is cosigned", async () => {
  const real = leaves(5), { w } = mk(real);
  const r1 = await w.onHead(head(real.slice(0, 3)));
  expect(r1.status).toBe("cosigned");
  if (r1.status === "cosigned") expect(verifyCosig(r1.sth, r1.sth.cosigs[0], wit.publicKey)).toBe(true);
  expect((await w.onHead(head(real))).status).toBe("cosigned");
  expect(w.head()?.treeSize).toBe(5);
});
test("a head not signed by the pinned log key is rejected, and so is a wrong logId", async () => {
  const real = leaves(3), { w } = mk(real);
  expect((await w.onHead(head(real, 1, generateKeypair().secretKey))).status).toBe("rejected");
  expect((await w.onHead({ ...head(real), logId: "other" })).status).toBe("rejected");
  expect(w.head()).toBeUndefined();
});
test("same size, different root: INCONSISTENT_STH with both heads, no cosign (scenario 5)", async () => {
  const real = leaves(4), fork = leaves(4, "evil");
  const { w } = mk(real);
  await w.onHead(head(real));
  const r = await w.onHead(head(fork, 2000)); // log key holder shows a forked head
  expect(r.status).toBe("inconsistent");
  if (r.status === "inconsistent") expect(r.alert).toMatchObject({ kind: "INCONSISTENT_STH", raisedBy: "w1" });
  expect(w.head()?.rootHash).toBe(head(real).rootHash);
  expect((await w.onHead(head(fork, 2000))).status).toBe("inconsistent");
  expect(await w.alerts({ app: "zzz" })).toHaveLength(1); // one alert per fork, and it applies to every release
});
test("a larger head that does not extend the last one is refused", async () => {
  const real = leaves(4), fork = [...leaves(3, "evil"), ...leaves(2, "x")];
  const { w } = mk(real.concat(leaves(3, "later")));
  await w.onHead(head(real));
  expect((await w.onHead(head(fork))).status).toBe("inconsistent");
  expect(w.head()?.treeSize).toBe(4);
});
test("never cosigns below the last size; unavailable proof is an error, not a cosign", async () => {
  const real = leaves(6), { w } = mk(real);
  await w.onHead(head(real));
  expect((await w.onHead(head(real.slice(0, 3)))).status).toBe("behind");
  const { w: w2 } = mk(real.slice(0, 4));
  await w2.onHead(head(real.slice(0, 4)));
  expect((await w2.onHead(head(real))).status).toBe("error"); // log cannot prove 4 -> 6
  expect(w2.head()?.treeSize).toBe(4);
});
test("heartbeat: an unchanged head is re-cosigned only after heartbeatMs", async () => {
  const real = leaves(3), { w, now } = mk(real);
  await w.onHead(head(real));
  now.t += 500; expect((await w.onHead(head(real))).status).toBe("unchanged");
  now.t += 600; const r = await w.onHead(head(real));
  expect(r.status).toBe("cosigned");
  if (r.status === "cosigned") expect(r.sth.cosigs[0].timestamp).toBe(new Date(now.t).toISOString());
});
test("HASH_MISMATCH + NOT_IN_LOG for a hash the log does not hold; only that hash's clients are told", async () => {
  const { w } = mk([]);
  await w.observe(obs(G, "c1")); await w.observe(obs(G, "c2"));
  const raised = await w.observe(obs(E, "c7"));
  expect(raised.map((a) => a.kind).sort()).toEqual(["HASH_MISMATCH", "NOT_IN_LOG"]);
  // c1..c12 (hash "good") are NOT blocked by c7's tampered binary...
  expect(await w.alerts({ app: "a", version: "1.0.0", platform: "win-x64", sha256: G })).toEqual([]);
  // ...but the dashboard sees everything and c7's own hash is flagged
  expect(await w.alerts({ app: "a" })).toHaveLength(2);
  expect((await w.alerts({ app: "a", version: "1.0.0", platform: "win-x64", sha256: E })).map((a) => a.kind)).toEqual(["NOT_IN_LOG"]);
});
test("two hashes that are BOTH in the log is a real equivocation: it blocks everyone with either", async () => {
  const { w } = mk([], { t: 1 }, [H1, H2]);
  await w.observe(obs(H1)); await w.observe(obs(H2));
  for (const h of [H1, H2]) expect((await w.alerts({ app: "a", version: "1.0.0", platform: "win-x64", sha256: h })).map((a) => a.kind)).toEqual(["HASH_MISMATCH"]);
});
test("log unreachable: no NOT_IN_LOG guess, and HASH_MISMATCH fails closed", async () => {
  const d: WitnessDeps = { consistency: async () => [], logHashes: async () => { throw new Error("down"); }, now: () => new Date(1) };
  const w = new WitnessCore({ id: "w1", secretKey: wit.secretKey, logId: LOG, logPublicKey: log.publicKey, heartbeatMs: 1 }, d);
  await w.observe(obs(H1));
  expect((await w.observe(obs(H2))).map((a) => a.kind)).toEqual(["HASH_MISMATCH"]);
  expect(await w.alerts({ app: "a", version: "1.0.0", platform: "win-x64", sha256: H1 })).toHaveLength(1);
});

test("reset forgets alerts and observations but keeps head history (a fork is still caught)", async () => {
  const real = leaves(4), fork = leaves(4, "evil"), { w } = mk(real, { t: 5000 }, [G]);
  await w.onHead(head(real)); await w.observe(obs(G)); await w.observe(obs(E));
  await w.onHead(head(fork, 2000));
  expect(await w.alerts({})).not.toHaveLength(0);
  w.reset();
  expect(await w.alerts({})).toHaveLength(0);
  expect((await w.onHead(head(fork, 2000))).status).toBe("inconsistent");
});

test("a restart keeps the last head, the fork evidence and the observations (snapshot round trip)", async () => {
  const real = leaves(4), fork = leaves(4, "evil");
  const { w } = mk(real, { t: 5000 }, [G]);
  await w.onHead(head(real)); await w.observe(obs(G)); await w.onHead(head(fork, 2000));
  const snap = JSON.parse(JSON.stringify(w.snapshot())); // through JSON, as the database would store it
  const { w: w2 } = mk(real, { t: 9000 }, [G]);
  w2.restore(snap);
  expect(await w2.alerts({})).toHaveLength(1);
  expect((await w2.onHead(head(fork, 2000))).status).toBe("inconsistent");   // still a fork after a restart, and not a second alert
  expect(await w2.alerts({})).toHaveLength(1);
  expect((await w2.onHead(head(real.slice(0, 2)))).status).toBe("behind");   // does not forget it already cosigned size 4
  expect((await w2.onHead(head(real))).status).toBe("cosigned");             // re-issues its cosig for the same head
});

// ---- findings from the independent (Codex) review ----
test("concurrent heads cannot roll the witness backward: they are processed one at a time", async () => {
  const real = leaves(5), now = { t: 5000 };
  const resolvers: (() => void)[] = [];
  const d: WitnessDeps = { consistency: (f, t) => new Promise((r) => resolvers.push(() => r(consistencyPath(real.slice(0, t), f)))), logHashes: async () => [], now: () => new Date(now.t) };
  const w = new WitnessCore({ id: "w1", secretKey: wit.secretKey, logId: LOG, logPublicKey: log.publicKey, heartbeatMs: 1000 }, d);
  await w.onHead(head(real.slice(0, 1)));
  const p3 = w.onHead(head(real.slice(0, 3))), p2 = w.onHead(head(real.slice(0, 2)));
  while (resolvers.length < 1) await new Promise((r) => setTimeout(r, 1));
  resolvers.shift()!();                                   // answer for 1->3 first
  await p3;
  while (resolvers.length < 1) await new Promise((r) => setTimeout(r, 1));
  resolvers.shift()!();
  expect((await p2).status).toBe("behind");               // 2 arrives after 3 was cosigned: refused
  expect(w.head()?.treeSize).toBe(3);
});
test("a witness that cannot persist its state refuses to sign", async () => {
  const real = leaves(3), { w } = mk(real);
  w.persist = async () => { throw new Error("disk full"); };
  const r = await w.onHead(head(real));
  expect(r.status).toBe("error");
  expect(w.head()).toBeUndefined();
  w.persist = async () => {};
  expect((await w.onHead(head(real))).status).toBe("cosigned"); // nothing was remembered from the failed attempt: still the first head
});
test("an observation with app=\"*\" cannot masquerade as a whole-log alert", async () => {
  const { w } = mk([], { t: 1 }, [G]);
  await w.observe({ ...obs(G), app: "*" });
  expect(await w.observe({ ...obs(E), app: "x".repeat(300) })).toEqual([]);   // oversized
  expect(await w.observe({ ...obs("nothex"), app: "a" })).toEqual([]);        // not a sha256
  expect(await w.alerts({ app: "a", version: "1.0.0", platform: "win-x64", sha256: G })).toEqual([]);
});
test("public input cannot grow state without bound", async () => {
  const { w } = mk([], { t: 1 }, [G]);
  for (let i = 0; i < 200; i++) await w.observe(obs(i.toString(16).padStart(64, "0")));
  expect((await w.alerts({})).length).toBeLessThanOrEqual(2 * 32); // 32 reports kept per release, at most two alerts each (not N^2)
});
test("an alert raised before the release was published is withdrawn once the log holds it", async () => {
  const logged: string[] = [];
  const d: WitnessDeps = { consistency: async () => [], logHashes: async () => logged, now: () => new Date(1) };
  const w = new WitnessCore({ id: "w1", secretKey: wit.secretKey, logId: LOG, logPublicKey: log.publicKey, heartbeatMs: 1 }, d);
  await w.observe(obs(G));                                           // seen before the vendor logs it
  expect(await w.alerts({ app: "a", version: "1.0.0", platform: "win-x64", sha256: G })).toHaveLength(1);
  logged.push(G);                                                    // vendor publishes
  expect(await w.alerts({ app: "a", version: "1.0.0", platform: "win-x64", sha256: G })).toEqual([]);
});
test("an observation whose lookup failed is re-checked later instead of forgotten", async () => {
  let up = false;
  const d: WitnessDeps = { consistency: async () => [], logHashes: async () => { if (!up) throw new Error("down"); return []; }, now: () => new Date(1) };
  const w = new WitnessCore({ id: "w1", secretKey: wit.secretKey, logId: LOG, logPublicKey: log.publicKey, heartbeatMs: 1 }, d);
  await w.observe(obs(E));
  up = true;
  expect((await w.alerts({ app: "a", version: "1.0.0", platform: "win-x64", sha256: E })).map((a) => a.kind)).toEqual(["NOT_IN_LOG"]);
});
test("two logged hashes that are not the first one seen still block (alerts are no longer pairwise)", async () => {
  const { w } = mk([], { t: 1 }, [H1, H2]);
  await w.observe(obs(E)); await w.observe(obs(H1)); await w.observe(obs(H2)); // E is unlogged, H1 and H2 are both logged
  for (const h of [H1, H2]) expect((await w.alerts({ app: "a", version: "1.0.0", platform: "win-x64", sha256: h })).map((a) => a.kind)).toEqual(["HASH_MISMATCH"]);
});

// ---- second Codex pass ----
const REL = { app: "a", version: "1.0.0", platform: "win-x64" };
test("concurrent /alerts requests cannot erase fork evidence (no index is held across an await)", async () => {
  const real = leaves(4), fork = leaves(4, "evil");
  let release!: () => void; const gate = new Promise<void>((r) => (release = r));
  const logged: string[] = [];
  const d: WitnessDeps = { consistency: async (f, t) => consistencyPath(real.slice(0, t), f), logHashes: async () => { await gate; return logged; }, now: () => new Date(1) };
  const w = new WitnessCore({ id: "w1", secretKey: wit.secretKey, logId: LOG, logPublicKey: log.publicKey, heartbeatMs: 1000 }, d);
  await w.onHead(head(real));
  // a client reports a hash the log does not hold yet; its lookup is parked on the gate
  const pending = w.observe(obs(G)); logged.push(G); release(); await pending;
  await w.onHead(head(fork, 2000));                                    // now a fork alert exists too
  const [a, b] = await Promise.all([w.alerts({ ...REL, sha256: G }), w.alerts({ ...REL, sha256: G })]);
  expect(a.some((x) => x.kind === "INCONSISTENT_STH")).toBe(true);
  expect(b.some((x) => x.kind === "INCONSISTENT_STH")).toBe(true);
  expect((await w.alerts({})).some((x) => x.kind === "INCONSISTENT_STH")).toBe(true);
});
test("junk reports cannot hide a real conflict: logged hashes are never crowded out", async () => {
  const { w } = mk([], { t: 1 }, [G, E]);
  await w.observe(obs(G));
  for (let i = 0; i < 100; i++) await w.observe(obs((i + 100).toString(16).padStart(64, "0")));  // junk, unlogged
  await w.observe(obs(E));                                                                       // a second LOGGED hash arrives after the flood
  for (const h of [G, E]) expect((await w.alerts({ ...REL, sha256: h })).map((x) => x.kind)).toContain("HASH_MISMATCH");
});
test("filling the alert history cannot disable detection (blocking does not read the alert list)", async () => {
  const { w } = mk([], { t: 1 }, [G, E]);
  for (let i = 0; i < 2500; i++) await w.observe({ ...obs(H(String.fromCharCode(97 + (i % 6)))), app: `junk${i}` });  // 2,500 absence alerts elsewhere
  await w.observe(obs(G)); await w.observe(obs(E));
  expect((await w.alerts({ ...REL, sha256: G })).map((x) => x.kind)).toContain("HASH_MISMATCH");
  expect((await w.alerts({})).length).toBeLessThanOrEqual(2000 + 1);                              // history is a bounded ring
});
test("a targeted alerts request costs one listing lookup, however much junk is stored", async () => {
  let calls = 0;
  const d: WitnessDeps = { consistency: async () => [], logHashes: async () => { calls++; return []; }, now: () => new Date(1) };
  const w = new WitnessCore({ id: "w1", secretKey: wit.secretKey, logId: LOG, logPublicKey: log.publicKey, heartbeatMs: 1000 }, d);
  for (let i = 0; i < 300; i++) await w.observe({ ...obs(H("a")), app: `junk${i}` });
  calls = 0;
  await w.alerts({ ...REL, sha256: G });
  expect(calls).toBeLessThanOrEqual(1);
});
test("a report made while the listing was unavailable survives a restart and is checked again", async () => {
  let up = false;
  const d: WitnessDeps = { consistency: async () => [], logHashes: async () => { if (!up) throw new Error("down"); return []; }, now: () => new Date(1) };
  const cfg = { id: "w1", secretKey: wit.secretKey, logId: LOG, logPublicKey: log.publicKey, heartbeatMs: 1000 };
  const w = new WitnessCore(cfg, d);
  await w.observe(obs(E));
  const snap = JSON.parse(JSON.stringify(w.snapshot()));
  const w2 = new WitnessCore(cfg, d); w2.restore(snap);
  up = true;
  expect((await w2.alerts({ ...REL, sha256: E })).map((x) => x.kind)).toEqual(["NOT_IN_LOG"]);
});
test("a head-processing error leaves the queue usable", async () => {
  const real = leaves(4), now = { t: 5000 };
  let boom = true;
  const d: WitnessDeps = { consistency: (f, t) => { if (boom) throw new Error("sync throw"); return Promise.resolve(consistencyPath(real.slice(0, t), f)); }, logHashes: async () => [], now: () => new Date(now.t) };
  const w = new WitnessCore({ id: "w1", secretKey: wit.secretKey, logId: LOG, logPublicKey: log.publicKey, heartbeatMs: 1000 }, d);
  await w.onHead(head(real.slice(0, 2)));
  expect((await w.onHead(head(real))).status).toBe("error");
  boom = false;
  expect((await w.onHead(head(real))).status).toBe("cosigned");
});

test("reports that arrive at the same time still see each other (HASH_MISMATCH is not lost to a race)", async () => {
  const { w } = mk([], { t: 1 }, [G, E]);
  const raised = (await Promise.all([w.observe(obs(G)), w.observe(obs(E)), w.observe(obs(H1))])).flat();
  expect(raised.filter((a) => a.kind === "HASH_MISMATCH").length).toBeGreaterThanOrEqual(2);
});
