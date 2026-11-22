import { expect, test } from "vitest";
import { devSecret, generateKeypair, leafHashOfEntry, publicKeyOf, rootHash, signEntry, verifyConsistency, verifyEntry, verifyInclusion, verifyLogSig } from "@uw/log-core";
import { createApp } from "./app.js";
import { logIdentity, newIdentity, vendorKeys } from "./log.js";
import { memoryStore, type LogStore } from "./store.js";

const vendor = generateKeypair();
const entry = (i: number) => signEntry({ app: "a", version: `1.0.${i}`, platform: "win-x64", sha256: "a".repeat(64), size: 1, url: "u", publishedAt: "2026-01-01T00:00:00.000Z", vendorKeyId: "k" }, vendor.secretKey);
const setup = (store: LogStore = memoryStore()) => { const id = newIdentity(); return { app: createApp(store, id, { k: vendor.publicKey }), id, store }; };
const post = (app: ReturnType<typeof createApp>, b: unknown) => app.request("/entries", { method: "POST", body: JSON.stringify(b) });
const json = async (r: Response | Promise<Response>) => (await r).json() as Promise<any>;

test("append returns the leaf, a log-signed head and a verifying inclusion proof (SPEC §5.1)", async () => {
  const { app, id } = setup();
  for (let i = 0; i < 7; i++) {
    const e = entry(i), r = await post(app, e), b = await json(r);
    expect(r.status).toBe(201);
    expect(b).toMatchObject({ idx: i, leafHash: leafHashOfEntry(e), sth: { treeSize: i + 1 }, inclusion: { leafIndex: i, treeSize: i + 1 } });
    expect(verifyLogSig(b.sth, id.publicKey)).toBe(true);
    expect(verifyInclusion(b.leafHash, i, i + 1, b.inclusion.path, b.sth.rootHash)).toBe(true);
  }
  expect((await json(app.request("/sth"))).treeSize).toBe(7);
});

test("proofs by hash verify against the head; old heads stay verifiable after growth", async () => {
  const { app, id } = setup();
  const entries = Array.from({ length: 5 }, (_, i) => entry(i));
  for (const e of entries.slice(0, 3)) await post(app, e);
  const old = await json(app.request("/sth"));
  for (const e of entries.slice(3)) await post(app, e);
  expect(await json(app.request("/sth/3"))).toEqual(old);
  expect(verifyLogSig(old, id.publicKey)).toBe(true);
  const h = leafHashOfEntry(entries[1]), p = await json(app.request(`/proof?leafHash=${h}&treeSize=3`));
  expect(verifyInclusion(h, p.leafIndex, 3, p.path, old.rootHash)).toBe(true);
  expect((await app.request(`/proof?leafHash=${leafHashOfEntry(entries[4])}&treeSize=3`)).status).toBe(404);
  expect(await json(app.request(`/key`))).toEqual({ logId: id.logId, publicKey: id.publicKey });
});

test("concurrent appends: gapless indexes, and every signed head matches the tree at its own size", async () => {
  const { app, id } = setup();
  const es = Array.from({ length: 25 }, (_, i) => entry(i));
  const rs = await Promise.all(es.map((e) => post(app, e)));
  expect(rs.every((r) => r.status === 201)).toBe(true);
  const heads = await json(app.request("/sths")), all = await json(app.request("/entries"));
  expect(all.map((l: any) => l.idx)).toEqual([...Array(25).keys()]);
  expect(heads.map((h: any) => h.treeSize)).toEqual([...Array(25).keys()].map((i) => i + 1));
  for (const h of heads) {
    expect(verifyLogSig(h, id.publicKey)).toBe(true);
    expect(h.rootHash).toBe(rootHash(all.slice(0, h.treeSize).map((l: any) => l.leafHash)));
  }
});

test("consistency proofs between heads verify; bad ranges are 400", async () => {
  const { app } = setup();
  for (let i = 0; i < 6; i++) await post(app, entry(i));
  const h3 = await json(app.request("/sth/3")), h6 = await json(app.request("/sth/6"));
  const c = await json(app.request("/consistency?from=3&to=6"));
  expect(verifyConsistency(3, 6, h3.rootHash, h6.rootHash, c.path)).toBe(true);
  for (const q of ["from=0&to=6", "from=4&to=3", "from=3&to=9", "from=x"]) expect((await app.request(`/consistency?${q}`)).status).toBe(400);
});

test("only entries signed by a registered vendor key can be appended", async () => {
  const { app } = setup(), good = entry(0);
  expect((await post(app, { ...good, vendorSig: "garbage" })).status).toBe(403);                                  // unsigned/garbage
  expect((await post(app, signEntry({ ...(({ vendorSig, ...r }) => r)(good) }, generateKeypair().secretKey))).status).toBe(403); // wrong key
  expect((await post(app, { ...good, vendorKeyId: "unknown" })).status).toBe(403);
  expect((await post(app, { ...good, vendorKeyId: "constructor" })).status).toBe(403);                            // prototype key
  expect((await post(app, { ...good, sha256: "b".repeat(64) })).status).toBe(403);                                // signed content changed
  expect((await app.request("/entries").then((r) => r.json())).length).toBe(0);                                    // nothing leaked in
  expect((await post(app, good)).status).toBe(201);
});

test("malformed and extra-field entries are 400, never stripped and stored", async () => {
  const { app } = setup();
  expect((await post(app, { app: "x" })).status).toBe(400);
  expect((await post(app, { ...entry(0), extra: "field" })).status).toBe(400);
  expect((await post(app, "nope")).status).toBe(400);
});

test("storage tampering is detected, not served: edited entry, edited hash", async () => {
  const mem = memoryStore(), { app } = setup(mem);
  for (let i = 0; i < 4; i++) await post(app, entry(i));
  const evil = (f: (l: any) => any): LogStore => ({ ...mem, all: async () => (await mem.all()).map((l) => (l.idx === 2 ? f(l) : l)) });
  for (const mutate of [(l: any) => ({ ...l, entry: { ...l.entry, version: "9.9.9" } }), (l: any) => ({ ...l, leafHash: "0".repeat(64) })]) {
    const t = createApp(evil(mutate), newIdentity(), { k: vendor.publicKey });
    for (const path of ["/entries", "/entries/2", "/proof?leafHash=" + "0".repeat(64) + "&treeSize=4", "/consistency?from=1&to=4"]) {
      const r = await t.request(path);
      expect(r.status, path).toBe(500);
      expect((await r.json()).error).toMatch(/tampered at leaf 2/);
    }
    expect((await post(t, entry(9))).status).toBe(500); // and it refuses to extend a tampered log
  }
});

test("bad indexes are 400/404, not 500", async () => {
  const { app } = setup();
  await post(app, entry(0));
  for (const p of ["abc", "1.5", "NaN"]) expect((await app.request(`/entries/${p}/proof`)).status, p).toBe(400);
  expect((await app.request("/entries/-1/proof")).status).toBe(404); // a valid integer, just out of range
  expect((await app.request("/entries/5/proof")).status).toBe(404);
  expect((await app.request("/proof?leafHash=00")).status).toBe(404);
  expect((await app.request("/sth/99")).status).toBe(404);
});

test("empty log: no head yet, proofs are 400", async () => {
  const { app } = setup();
  expect((await app.request("/sth")).status).toBe(404);
  expect((await app.request("/proof?leafHash=" + "0".repeat(64))).status).toBe(400);
  expect(await json(app.request("/sths"))).toEqual([]);
});

test("identity and vendor keys are required unless DEV=1", () => {
  expect(() => logIdentity({})).toThrow(/LOG_SECRET_KEY is required/);
  expect(() => vendorKeys({})).toThrow(/VENDOR_PUBLIC_KEYS is required/);
  const dev = { DEV: "1" };
  expect(logIdentity(dev).publicKey).toBe(publicKeyOf(devSecret("log")));
  expect(vendorKeys(dev)).toEqual({ demo: publicKeyOf(devSecret("vendor")) });
  const k = generateKeypair();
  expect(logIdentity({ LOG_SECRET_KEY: k.secretKey, LOG_ID: "x" })).toEqual({ logId: "x", secretKey: k.secretKey, publicKey: k.publicKey });
  expect(vendorKeys({ VENDOR_PUBLIC_KEYS: JSON.stringify({ a: k.publicKey }) }).a).toBe(k.publicKey);
  expect(() => vendorKeys({ VENDOR_PUBLIC_KEYS: "[1]" })).toThrow();
  expect(verifyEntry(signEntry({ app: "a", version: "1.0.0", platform: "win-x64", sha256: "a".repeat(64), size: 1, url: "u", publishedAt: "2026-01-01T00:00:00.000Z", vendorKeyId: "demo" }, devSecret("vendor")), vendorKeys(dev).demo)).toBe(true);
});
