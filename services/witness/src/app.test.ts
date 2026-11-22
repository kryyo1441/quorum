import { expect, test } from "vitest";
import { createApp } from "./app.js";
import { stubCore } from "./core.js";

const obs = (sha256: string, who: string) => ({ app: "a", version: "1.0.0", platform: "win-x64", sha256, sthRoot: "", sthSize: 0, clientPseudonym: who, observedAt: new Date().toISOString() });
const post = (app: ReturnType<typeof createApp>, b: unknown) => app.request("/observations", { method: "POST", body: JSON.stringify(b) });

test("same hash is quiet, a second distinct hash raises HASH_MISMATCH", async () => {
  const app = createApp("w1", stubCore("w1"));
  expect((await (await post(app, obs("aa", "c1"))).json()).raised).toEqual([]);
  expect((await (await post(app, obs("aa", "c2"))).json()).raised).toEqual([]);
  const r = (await (await post(app, obs("bb", "c7"))).json()).raised;
  expect(r).toHaveLength(1);
  expect(r[0]).toMatchObject({ kind: "HASH_MISMATCH", raisedBy: "w1" });
  expect(await (await app.request("/alerts?app=a")).json()).toHaveLength(1);
});
test("rejects malformed observation, 404 head, 501 gossip", async () => {
  const app = createApp("w1", stubCore("w1"));
  expect((await post(app, { nope: 1 })).status).toBe(400);
  expect((await app.request("/sth")).status).toBe(404);
  expect((await app.request("/gossip", { method: "POST" })).status).toBe(501);
});
