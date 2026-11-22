import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { cosign, generateKeypair, leafHashOfEntry, signEntry } from "@uw/log-core";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { checkUpdate, compareVersions, verifyUpdate, type Deps, type VerifyConfig } from "./verify.js";

const v = JSON.parse(readFileSync(new URL("../../../fixtures/vectors.json", import.meta.url), "utf8"));
const binaryOf = (i: number) => new TextEncoder().encode(`binary-${i}`); // matches fixtures/generate.ts
const NOW = Date.parse("2026-01-01T00:02:00.000Z"); // 1 min after the fixture cosigs

type World = { sth?: any; alerts?: Record<string, unknown>; down?: string[]; proofOverride?: any };
/** In-process "network": the fixture log + three witnesses. */
function world(w: World = {}): Deps {
  const f = async (input: any) => {
    const u = new URL(String(input)), json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s });
    if (w.down?.includes(u.host)) throw new Error("ECONNREFUSED");
    if (u.host === "log") {
      if (u.pathname === "/sth") return json(w.sth ?? v.sth);
      if (u.pathname === "/proof") {
        const idx = v.leaves.indexOf(u.searchParams.get("leafHash"));
        return idx < 0 ? json({ error: "no" }, 404) : json(w.proofOverride ?? v.inclusion[idx]);
      }
    }
    if (u.pathname === "/alerts") return json(w.alerts?.[u.host] ?? []);
    return json({}, 404);
  };
  return { fetch: f as typeof fetch, now: () => NOW };
}
const cfg = (o: Partial<VerifyConfig> = {}): VerifyConfig => ({
  logUrl: "http://log", threshold: 2, logPublicKey: v.keys.log.publicKey, vendorPublicKeys: { vendor: v.keys.vendor.publicKey },
  witnesses: ["w1", "w2", "w3"].map((id) => ({ id, url: `http://${id}`, publicKey: v.keys[id].publicKey })), ...o,
});
const run = (i: number, c = cfg(), d = world(), m = v.entries[i], bin = binaryOf(i)) => verifyUpdate(bin, m, c, d);
const fails = async (p: ReturnType<typeof run>, reason: string) => expect(await p).toMatchObject({ ok: false, reason });

test("happy path: every fixture entry verifies", async () => {
  for (let i = 0; i < 16; i++) expect(await run(i), `entry ${i}`).toMatchObject({ ok: true });
});

test("#1 server swaps the binary under the same manifest -> HASH_MISMATCH", async () => fails(run(3, cfg(), world(), v.entries[3], binaryOf(4)), "HASH_MISMATCH"));
test("#2 forged manifest (new hash, same signature) -> BAD_VENDOR_SIG", async () => {
  const evil = new TextEncoder().encode("evil"), m = { ...v.entries[3], sha256: bytesToHex(sha256(evil)) };
  await fails(run(3, cfg(), world(), m, evil), "BAD_VENDOR_SIG");
});
test("unknown vendor key id -> BAD_VENDOR_SIG", async () => fails(run(3, cfg({ vendorPublicKeys: {} })), "BAD_VENDOR_SIG"));
test("#3 stolen vendor key, signed but never logged -> NOT_IN_LOG", async () => {
  const k = generateKeypair(), evil = new TextEncoder().encode("evil");
  const m = signEntry({ ...(({ vendorSig, ...r }) => r)(v.entries[0]), sha256: bytesToHex(sha256(evil)), version: "9.9.9" }, k.secretKey);
  await fails(run(0, cfg({ vendorPublicKeys: { vendor: k.publicKey } }), world(), m, evil), "NOT_IN_LOG");
  expect(leafHashOfEntry(m)).not.toBe(v.leaves[0]);
});
test("#5/#7 one compromised witness cosigns alone -> INSUFFICIENT_COSIGS", async () => fails(run(2, cfg(), world({ sth: v.tampered.sthOneCosigOnly })), "INSUFFICIENT_COSIGS"));
test("one corrupted cosig still passes at k=2 but not k=3", async () => {
  expect(await run(2, cfg(), world({ sth: v.tampered.sthOneCosigBad }))).toMatchObject({ ok: true });
  await fails(run(2, cfg({ threshold: 3 }), world({ sth: v.tampered.sthOneCosigBad })), "INSUFFICIENT_COSIGS");
});
test("duplicate cosigs from one witness count once", async () => {
  const c = v.sth.cosigs[0];
  await fails(run(2, cfg(), world({ sth: { ...v.sth, cosigs: [c, c, c] } })), "INSUFFICIENT_COSIGS");
});
test("a cosig relabeled to another witness is rejected", async () => fails(run(2, cfg({ threshold: 3 }), world({ sth: v.tampered.sthCosigWrongWitness })), "INSUFFICIENT_COSIGS"));
test("old cosignatures -> STALE_STH (24h default and 5-minute demo window)", async () => {
  const late = { ...world(), now: () => NOW + 25 * 3600 * 1000 };
  await fails(run(2, cfg(), late), "STALE_STH");
  const demo = { ...world(), now: () => NOW + 6 * 60 * 1000 };
  await fails(run(2, cfg({ maxAgeMs: 5 * 60 * 1000 }), demo), "STALE_STH");
  expect(await run(2, cfg({ maxAgeMs: 5 * 60 * 1000 }))).toMatchObject({ ok: true });
});
test("cosigs from the future are not fresh", async () => fails(run(2, cfg({ maxAgeMs: 1000 }), { ...world(), now: () => NOW - 3600 * 1000 }), "STALE_STH"));
test("tampered head or proof -> BAD_INCLUSION_PROOF", async () => {
  await fails(run(5, cfg(), world({ sth: v.tampered.sthRootChanged })), "BAD_INCLUSION_PROOF");
  await fails(run(5, cfg(), world({ sth: v.tampered.sthBadLogSig })), "BAD_INCLUSION_PROOF");
  await fails(run(5, cfg(), world({ proofOverride: v.tampered.inclusionPathFlipped })), "BAD_INCLUSION_PROOF");
  await fails(run(5, cfg(), world({ proofOverride: v.tampered.inclusionWrongIndex })), "BAD_INCLUSION_PROOF");
  await fails(run(5, cfg(), world({ proofOverride: { leafIndex: "x", path: [] } })), "BAD_INCLUSION_PROOF");
});
test("a head signed by the wrong log key is rejected", async () => fails(run(5, cfg({ logPublicKey: generateKeypair().publicKey })), "BAD_INCLUSION_PROOF"));
test("#10 an open split-view alert on any witness -> SPLIT_VIEW", async () => {
  await fails(run(5, cfg(), world({ alerts: { w3: [{ kind: "HASH_MISMATCH" }] } })), "SPLIT_VIEW");
});
test("#8 log unreachable fails closed as NOT_IN_LOG with a clear detail", async () => {
  const r = await run(5, cfg(), world({ down: ["log"] }));
  expect(r).toMatchObject({ ok: false, reason: "NOT_IN_LOG" });
  expect((r as any).detail).toMatch(/log unreachable/);
});
test("#8 one witness unreachable fails closed as INSUFFICIENT_COSIGS", async () => {
  const r = await run(5, cfg(), world({ down: ["w2"] }));
  expect(r).toMatchObject({ ok: false, reason: "INSUFFICIENT_COSIGS" });
  expect((r as any).detail).toMatch(/w2 unreachable/);
});
test("garbage from the log never throws and never passes", async () => {
  const bad = { fetch: (async () => new Response("not json", { status: 200 })) as typeof fetch, now: () => NOW };
  expect(await run(5, cfg(), bad)).toMatchObject({ ok: false });
  const boom = { fetch: (async () => { throw new TypeError("boom"); }) as typeof fetch, now: () => NOW };
  expect(await run(5, cfg(), boom)).toMatchObject({ ok: false });
});

// ---- added after the independent review ----
const WIN = { app: "notepad-minus", platform: "win-x64" }; // fixture entries i % 3 === 0 are win-x64 (2.0.0, 2.0.3, ..., 2.0.12, 2.0.15)

test("#6 REAL downgrade: an old release with a valid proof against today's fresh head is blocked", async () => {
  // entries[3] (2.0.3) is in the log, validly signed, and provable against the current head, but the client runs 2.0.9.
  const r = await run(3, cfg({ expected: { ...WIN, installedVersion: "2.0.9" } }));
  expect(r).toMatchObject({ ok: false, reason: "STALE_STH" });
  expect((r as any).detail).toMatch(/downgrade/);
  // control: the same release verifies when the client is older than it
  expect(await run(3, cfg({ expected: { ...WIN, installedVersion: "2.0.2" } }))).toMatchObject({ ok: true });
  // upgrade path
  expect(await run(12, cfg({ expected: { ...WIN, installedVersion: "2.0.9" } }))).toMatchObject({ ok: true });
});
test("reinstalling the same version is not an update", async () => fails(run(12, cfg({ expected: { ...WIN, installedVersion: "2.0.12" } })), "STALE_STH"));
test("unparseable versions fail closed", async () => fails(run(12, cfg({ expected: { ...WIN, installedVersion: "banana" } })), "STALE_STH"));
test("cross-platform and cross-app substitution are blocked when the install target is pinned", async () => {
  await fails(run(2, cfg({ expected: WIN })), "NOT_IN_LOG");                                  // entries[2] is linux-x64
  await fails(run(3, cfg({ expected: { app: "other-app", platform: "win-x64" } })), "NOT_IN_LOG");
  expect(await run(3, cfg({ expected: WIN }))).toMatchObject({ ok: true });
});
test("without `expected` the target check is reported as SKIPPED, not silently passed", async () => {
  const { checks } = await checkUpdate(binaryOf(3), v.entries[3], cfg(), world());
  expect(checks.find((c) => c.id === "target")).toMatchObject({ status: "skip" });
});
test("compareVersions is numeric, not lexicographic, and orders prereleases below the release", () => {
  expect(compareVersions("2.0.10", "2.0.9")).toBeGreaterThan(0);
  expect(compareVersions("2.1.0", "2.0.99")).toBeGreaterThan(0);
  expect(compareVersions("2.1.0-rc1", "2.1.0")).toBeLessThan(0);
  expect(compareVersions("2.1.0", "2.1.0")).toBe(0);
  expect(compareVersions("x", "1.0.0")).toBeUndefined();
});

test("nonsense config fails closed: threshold 0, negative, fractional, NaN, above n; duplicate witnesses; bad maxAgeMs", async () => {
  const noCosigs = world({ sth: { ...v.sth, cosigs: [] } });
  for (const t of [0, -1, 1.5, NaN, 4, Infinity]) await fails(run(2, cfg({ threshold: t }), noCosigs), "INSUFFICIENT_COSIGS");
  await fails(run(2, cfg({ threshold: 0, witnesses: [] }), noCosigs), "INSUFFICIENT_COSIGS");
  const dup = cfg(); dup.witnesses[1] = { ...dup.witnesses[0], id: "w2" };                       // same key under two ids
  await fails(run(2, dup), "INSUFFICIENT_COSIGS");
  for (const m of [Infinity, 0, -5, NaN]) await fails(run(2, cfg({ maxAgeMs: m })), "STALE_STH");
  expect(await run(2, cfg({ maxAgeMs: Infinity }), { ...world(), now: () => NOW + 365 * 24 * 3600 * 1000 })).toMatchObject({ ok: false });
});

test("newest valid cosig per witness counts (heartbeat re-cosign must not fail on the older one)", async () => {
  const body = { logId: v.sth.logId, treeSize: v.sth.treeSize, rootHash: v.sth.rootHash, timestamp: v.sth.timestamp };
  const old = cosign(body, "w1", v.keys.w1.secretKey, new Date(NOW - 25 * 3600 * 1000).toISOString());
  const sth = { ...v.sth, cosigs: [old, v.sth.cosigs[0], v.sth.cosigs[1]] }; // [w1 old, w1 fresh, w2 fresh]
  expect(await run(2, cfg(), world({ sth }))).toMatchObject({ ok: true });
});
test("cosigs dated far in the future are not fresh (only a small clock skew is tolerated)", async () => {
  await fails(run(2, cfg(), { ...world(), now: () => NOW - 23 * 3600 * 1000 }), "STALE_STH");
  expect(await run(2, cfg(), { ...world(), now: () => NOW - 4 * 60 * 1000 })).toMatchObject({ ok: true });
});

test("malformed manifests (lone surrogate, extra field, wrong types) fail as BAD_VENDOR_SIG and never throw", async () => {
  for (const m of [{ ...v.entries[3], app: "\uD800" }, { ...v.entries[3], extra: 1 }, { ...v.entries[3], size: "big" }, null, "x", {}])
    await fails(run(3, cfg(), world(), m as any), "BAD_VENDOR_SIG");
  const { checks } = await checkUpdate(binaryOf(3), { ...v.entries[3], app: "\uD800" }, cfg(), world());
  expect(checks.map((c) => c.id)).toHaveLength(8); // every check still reported
});
test("prototype-ish vendor key ids and a proof response's own treeSize/leafHash claims are ignored", async () => {
  await fails(run(3, cfg({ vendorPublicKeys: {} }), world(), { ...v.entries[3], vendorKeyId: "constructor" }), "BAD_VENDOR_SIG");
  const lying = { ...v.inclusion[3], treeSize: 999, leafHash: "f".repeat(64) };
  expect(await run(3, cfg(), world({ proofOverride: lying }))).toMatchObject({ ok: true });
});
