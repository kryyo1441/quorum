import { CompactTree, consistencyPath, generateKeypair, leafHashOfEntry, signEntry, signSTH } from "@uw/log-core";
import { expect, test } from "vitest";
import { Monitor } from "./monitor.js";

const log = generateKeypair(), vendor = generateKeypair(), LOG = "log-1";
const rel = (version: string, sha256: string, sk = vendor.secretKey) => signEntry({ app: "a", version, platform: "win-x64", sha256, size: 1, url: "u", publishedAt: "2026-01-01T00:00:00.000Z", vendorKeyId: "v" }, sk);
function mk(entries: ReturnType<typeof rel>[]) {
  const st = { entries, tamper: undefined as undefined | ((i: number) => void) };
  const m = new Monitor({ logId: LOG, logPublicKey: log.publicKey, vendorPublicKeys: { v: vendor.publicKey } }, {
    entries: async () => st.entries.map((entry, idx) => ({ idx, entry, leafHash: leafHashOfEntry(entry) })),
    head: async () => { const hs = st.entries.map(leafHashOfEntry); return signSTH({ logId: LOG, treeSize: hs.length, rootHash: new CompactTree(hs).root(), timestamp: "t" }, log.secretKey); },
    consistency: async (f, t) => consistencyPath(st.entries.slice(0, t).map(leafHashOfEntry), f),
    now: () => new Date(1),
  });
  return { m, st };
}
test("approved releases are quiet; an unapproved entry (stolen key, scenario 4) raises UNAPPROVED_RELEASE once", async () => {
  const good = rel("1.0.0", "a".repeat(64)), { m, st } = mk([good]);
  m.approve({ app: "a", version: "1.0.0", platform: "win-x64", sha256: "a".repeat(64) });
  expect(await m.poll()).toEqual([]);
  st.entries.push(rel("1.0.1", "b".repeat(64)));
  const r = await m.poll();
  expect(r).toHaveLength(1);
  expect(r[0]).toMatchObject({ kind: "UNAPPROVED_RELEASE", version: "1.0.1", raisedBy: "monitor" });
  expect(await m.poll()).toEqual([]);
});
test("an entry whose version/hash differs from the approved one is unapproved even if the vendor signed it", async () => {
  const { m } = mk([rel("1.0.0", "c".repeat(64))]);
  m.approve({ app: "a", version: "1.0.0", platform: "win-x64", sha256: "a".repeat(64) });
  expect((await m.poll())[0].kind).toBe("UNAPPROVED_RELEASE");
});
test("a log that rewrites history between polls is reported", async () => {
  const a = rel("1.0.0", "a".repeat(64)), { m, st } = mk([a, rel("1.0.1", "b".repeat(64))]);
  m.approve({ app: "a", version: "1.0.0", platform: "win-x64", sha256: "a".repeat(64) });
  m.approve({ app: "a", version: "1.0.1", platform: "win-x64", sha256: "b".repeat(64) });
  await m.poll();
  st.entries = [rel("1.0.0", "d".repeat(64)), st.entries[1], rel("1.0.2", "e".repeat(64))];
  expect((await m.poll()).map((x) => x.kind)).toContain("INCONSISTENT_STH");
});
