// Runs the log against REAL Postgres: set TEST_DATABASE_URL to a server you can create databases on (e.g. postgresql://uw:uw@localhost:5432/uw). Skipped otherwise.
import { execSync } from "node:child_process";
import { PrismaClient } from "@prisma/client";
import pg from "pg";
import { afterAll, beforeAll, expect, test } from "vitest";
import { cosign, generateKeypair, leafHashOfEntry, signEntry, verifyInclusion, verifyLogSig } from "@uw/log-core";
import { createApp } from "./app.js";
import { newIdentity } from "./log.js";
import { prismaStore } from "./prisma-store.js";

const admin = process.env.TEST_DATABASE_URL, name = `uw_test_${Date.now()}`;
const urlFor = (db: string) => { const u = new URL(admin!); u.pathname = `/${db}`; return u.toString(); };
const vendor = generateKeypair(), witness = generateKeypair(), id = newIdentity();
const entry = (i: number) => signEntry({ app: "a", version: `1.0.${i}`, platform: "win-x64", sha256: "a".repeat(64), size: 1, url: "u", publishedAt: "2026-01-01T00:00:00.000Z", vendorKeyId: "k" }, vendor.secretKey);
let db: PrismaClient, app: ReturnType<typeof createApp>;
const json = async (r: Response | Promise<Response>) => (await r).json() as Promise<any>;

beforeAll(async () => {
  if (!admin) return;
  const c = new pg.Client({ connectionString: admin }); await c.connect(); await c.query(`CREATE DATABASE ${name}`); await c.end();
  execSync("npx prisma migrate deploy", { cwd: new URL("..", import.meta.url).pathname, env: { ...process.env, DATABASE_URL: urlFor(name) }, stdio: "pipe" });
  db = new PrismaClient({ datasourceUrl: urlFor(name) });
  app = createApp(prismaStore(id.logId, db), id, { k: vendor.publicKey }, { w1: witness.publicKey });
}, 120_000);
afterAll(async () => {
  if (!admin) return;
  await db?.$disconnect();
  const c = new pg.Client({ connectionString: admin }); await c.connect(); await c.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`); await c.end();
});

test.skipIf(!admin)("Postgres: concurrent appends are gapless, heads verify, cosigs persist, a restarted log reads the same tree", async () => {
  const rs = await Promise.all(Array.from({ length: 6 }, (_, i) => app.request("/entries", { method: "POST", body: JSON.stringify(entry(i)) })));
  expect(rs.map((r) => r.status)).toEqual(Array(6).fill(201));
  const leaves = await json(app.request("/entries"));
  expect(leaves.map((l: any) => l.idx)).toEqual([0, 1, 2, 3, 4, 5]);
  const head = await json(app.request("/sth"));
  expect(head.treeSize).toBe(6);
  expect(verifyLogSig(head, id.publicKey)).toBe(true);
  const p = await json(app.request(`/entries/3/proof?treeSize=6`));
  expect(verifyInclusion(leafHashOfEntry(leaves[3].entry), 3, 6, p.path, head.rootHash)).toBe(true);
  expect((await app.request("/sth/6/cosigs", { method: "POST", body: JSON.stringify(cosign(head, "w1", witness.secretKey, new Date().toISOString())) })).status).toBe(201);
  expect((await json(app.request("/sth/6"))).cosigs).toHaveLength(1);
  const restarted = createApp(prismaStore(id.logId, db), id, { k: vendor.publicKey }, {});
  expect((await restarted.request("/entries", { method: "POST", body: JSON.stringify(entry(9)) })).status).toBe(201);
  expect((await json(restarted.request("/sth"))).treeSize).toBe(7);
}, 60_000);

test.skipIf(!admin)("Postgres: a leaf edited in the database (entry only) is detected on read, not served (SPEC #9)", async () => {
  await db.$executeRawUnsafe(`UPDATE "Leaf" SET entry = jsonb_set(entry, '{sha256}', '"${"b".repeat(64)}"') WHERE idx = 2`);
  const r = await app.request("/entries");
  expect(r.status).toBe(500);
  expect((await r.json()).error).toMatch(/tampered at leaf 2/);
});
