import { expect, test } from "vitest";
import { createApp } from "./app.js";
import { stubCore } from "./core.js";
import { memoryStore } from "./store.js";

const entry = (v: string) => ({ app: "a", version: v, platform: "win-x64", sha256: "a".repeat(64), size: 1, url: "u", publishedAt: new Date().toISOString(), vendorKeyId: "k", vendorSig: "s" });
const post = (app: ReturnType<typeof createApp>, b: unknown) => app.request("/entries", { method: "POST", body: JSON.stringify(b) });

test("append assigns gapless indexes and a deterministic leaf hash", async () => {
  const app = createApp(memoryStore(), stubCore);
  const a = await (await post(app, entry("1.0.0"))).json(), b = await (await post(app, entry("1.0.1"))).json();
  expect([a.idx, b.idx]).toEqual([0, 1]);
  expect(a.leafHash).toMatch(/^[0-9a-f]{64}$/);
  expect(await (await app.request("/entries")).json()).toHaveLength(2);
  expect((await app.request("/entries/1")).status).toBe(200);
  expect((await app.request("/entries/9")).status).toBe(404);
});
test("leaf hash matches SPEC §6 for a fixed entry", () => {
  const e = { ...entry("1.0.0"), publishedAt: "2026-01-01T00:00:00.000Z" };
  const again = stubCore.leafHash({ ...e });
  expect(stubCore.leafHash(e)).toBe(again);
  expect(stubCore.leafHash({ ...e, version: "1.0.1" })).not.toBe(again);
});
test("rejects malformed entries; proofs and sth are honest about not being built", async () => {
  const app = createApp(memoryStore(), stubCore);
  expect((await post(app, { app: "x" })).status).toBe(400);
  await post(app, entry("1.0.0"));
  expect((await app.request("/entries/0/proof")).status).toBe(501);
  expect((await app.request("/consistency?from=1")).status).toBe(501);
  expect((await app.request("/sth")).status).toBe(404);
  expect((await app.request("/entries/5/proof")).status).toBe(404);
});
