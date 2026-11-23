import { generateKeypair, signSTH } from "@uw/log-core";
import { expect, test } from "vitest";
import { pgState } from "./state.js";

const url = process.env.TEST_DATABASE_URL;
test.skipIf(!url)("state round-trips through Postgres in a per-witness schema and survives a reconnect", async () => {
  const k = generateKeypair(), head = signSTH({ logId: "l", treeSize: 3, rootHash: "a".repeat(64), timestamp: "2026-06-01T00:00:00.000Z" }, k.secretKey);
  const id = `t${Date.now()}`, a = await pgState(url!, id);
  expect(await a.load()).toBeUndefined();
  await a.save({ last: head, heads: [head], alerts: [], observations: [] });
  await a.close();
  const b = await pgState(url!, id);
  expect((await b.load())?.last?.treeSize).toBe(3);
  await b.close();
});
