import { generateKeypair } from "@uw/log-core";
import { Monitor } from "@uw/witness-core";
import { expect, test } from "vitest";
import { createApp } from "./app.js";

const k = generateKeypair();
const m = () => new Monitor({ logId: "l", logPublicKey: k.publicKey, vendorPublicKeys: {} }, { entries: async () => [], head: async () => { throw new Error("x"); }, consistency: async () => [], now: () => new Date() });
const body = { app: "a", version: "1", platform: "win-x64", sha256: "a".repeat(64) };
test("approving needs the monitor token; the release key alone is not enough", async () => {
  const app = createApp(m(), "s3cret");
  const post = (auth?: string, b: unknown = body) => app.request("/approved", { method: "POST", body: JSON.stringify(b), headers: auth ? { authorization: auth } : {} });
  expect((await post()).status).toBe(401);
  expect((await post("Bearer wrong")).status).toBe(401);
  expect((await post("Bearer s3cret", { ...body, sha256: "x" })).status).toBe(400);
  expect((await post("Bearer s3cret")).status).toBe(201);
  expect(await (await app.request("/alerts")).json()).toEqual([]);
});
