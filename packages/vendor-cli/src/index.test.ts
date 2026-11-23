import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";
import { generateKeypair, verifyEntry } from "@uw/log-core";
import { createApp } from "../../../services/log-server/src/app.js";
import { newIdentity } from "../../../services/log-server/src/log.js";
import { memoryStore } from "../../../services/log-server/src/store.js";
import { publish } from "./index.js";

const vendor = generateKeypair(), dir = mkdtempSync(join(tmpdir(), "uw-"));
const file = join(dir, "app.bin"); writeFileSync(file, "release bytes");
const base = { file, app: "a", version: "1.0.0", platform: "win-x64" as const, url: "https://cdn/a", keyId: "k", logUrl: "http://log" };
const via = (app: ReturnType<typeof createApp>) => ((u: string, i?: RequestInit) => app.request(new URL(u).pathname, i)) as unknown as typeof fetch;

test("publish hashes the file, signs it, and the log accepts and returns its position", async () => {
  const app = createApp(memoryStore(), newIdentity(), { k: vendor.publicKey });
  const p = await publish({ ...base, secretKey: vendor.secretKey }, via(app));
  expect(p).toMatchObject({ leafIndex: 0, treeSize: 1 });
  expect(p.entry.size).toBe(13);
  expect(verifyEntry(p.entry, vendor.publicKey)).toBe(true);
});
test("a key the log does not know is refused loudly", async () => {
  const app = createApp(memoryStore(), newIdentity(), { k: vendor.publicKey });
  await expect(publish({ ...base, secretKey: generateKeypair().secretKey }, via(app))).rejects.toThrow(/403/);
});
