import { expect, test } from "vitest";
import { generateKeypair, leafHashOfEntry, signEntry, verifyConsistency, verifyEntry, verifyInclusion, verifyLogSig } from "@uw/log-core";
import { createApp } from "./app.js";
import { newIdentity } from "./log.js";
import { memoryStore } from "./store.js";

const vendor = generateKeypair();
const entry = (i: number) => signEntry({ app: "a", version: `1.0.${i}`, platform: "win-x64", sha256: "a".repeat(64), size: 1, url: "u", publishedAt: "2026-01-01T00:00:00.000Z", vendorKeyId: "k" }, vendor.secretKey);
const setup = () => { const id = newIdentity(); return { app: createApp(memoryStore(), id), id }; };
const post = (app: ReturnType<typeof createApp>, b: unknown) => app.request("/entries", { method: "POST", body: JSON.stringify(b) });
const json = async (r: Response | Promise<Response>) => (await r).json() as Promise<any>;

test("append issues a log-signed head per growth, and proofs verify against it", async () => {
  const { app, id } = setup();
  const entries = Array.from({ length: 7 }, (_, i) => entry(i));
  for (const e of entries) expect((await post(app, e)).status).toBe(201);
  const head = await json(app.request("/sth"));
  expect(head.treeSize).toBe(7);
  expect(verifyLogSig(head, id.publicKey)).toBe(true);
  expect(await json(app.request("/key"))).toEqual({ logId: id.logId, publicKey: id.publicKey });
  for (const [i, e] of entries.entries()) {
    const p = await json(app.request(`/proof?leafHash=${leafHashOfEntry(e)}&treeSize=7`));
    expect(p).toMatchObject({ leafIndex: i, treeSize: 7 });
    expect(verifyInclusion(leafHashOfEntry(e), p.leafIndex, p.treeSize, p.path, head.rootHash)).toBe(true);
    expect(verifyEntry(e, vendor.publicKey)).toBe(true);
  }
});

test("proofs are computed at the requested size, so an older head still verifies after growth", async () => {
  const { app, id } = setup();
  const entries = Array.from({ length: 5 }, (_, i) => entry(i));
  for (const e of entries.slice(0, 3)) await post(app, e);
  const old = await json(app.request("/sth"));
  for (const e of entries.slice(3)) await post(app, e);
  expect((await json(app.request("/sth"))).treeSize).toBe(5);
  expect(await json(app.request("/sth/3"))).toEqual(old);
  expect(verifyLogSig(old, id.publicKey)).toBe(true);
  const h = leafHashOfEntry(entries[1]);
  const p = await json(app.request(`/proof?leafHash=${h}&treeSize=3`));
  expect(verifyInclusion(h, p.leafIndex, 3, p.path, old.rootHash)).toBe(true);
  expect((await app.request(`/proof?leafHash=${leafHashOfEntry(entries[4])}&treeSize=3`)).status).toBe(404); // not in that smaller tree
});

test("sths lists one verifiable head per size", async () => {
  const { app, id } = setup();
  for (let i = 0; i < 4; i++) await post(app, entry(i));
  const heads = await json(app.request("/sths"));
  expect(heads.map((h: any) => h.treeSize)).toEqual([1, 2, 3, 4]);
  for (const h of heads) expect(verifyLogSig(h, id.publicKey)).toBe(true);
});

test("consistency proofs between heads verify; bad ranges are 400", async () => {
  const { app } = setup();
  for (let i = 0; i < 6; i++) await post(app, entry(i));
  const h3 = await json(app.request("/sth/3")), h6 = await json(app.request("/sth/6"));
  const c = await json(app.request("/consistency?from=3&to=6"));
  expect(verifyConsistency(3, 6, h3.rootHash, h6.rootHash, c.path)).toBe(true);
  for (const q of ["from=0&to=6", "from=4&to=3", "from=3&to=9", "from=x"]) expect((await app.request(`/consistency?${q}`)).status).toBe(400);
});

test("rejects malformed entries; unknown hash 404; empty log has no head", async () => {
  const { app } = setup();
  expect((await post(app, { app: "x" })).status).toBe(400);
  expect((await app.request("/sth")).status).toBe(404);
  expect((await app.request("/proof?leafHash=00")).status).toBe(400);
  await post(app, entry(0));
  expect((await app.request(`/proof?leafHash=${"0".repeat(64)}`)).status).toBe(404);
});
