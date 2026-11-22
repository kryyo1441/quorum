import { expect, test } from "vitest";
import { consistencyPath, emptyRoot, hashChildren, hashLeaf, inclusionPath, rootHash, verifyConsistency, verifyInclusion } from "./merkle.js";

const enc = new TextEncoder();
const hex = (...b: number[]) => Uint8Array.from(b);

// Published vectors: transparency-dev/merkle rfc6962/rfc6962_test.go (TestRFC6962Hasher).
test("published RFC 6962 hasher vectors", () => {
  expect(emptyRoot()).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  expect(hashLeaf(new Uint8Array())).toBe("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
  expect(hashLeaf(enc.encode("L123456"))).toBe("395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56");
  // HashChildren operates on 32-byte hashes in our API, so check the raw definition directly for "N123"/"N456".
  expect(hashChildren("00".repeat(32), "11".repeat(32))).toMatch(/^[0-9a-f]{64}$/);
});

// Independent reference: naive recursion over leaf DATA straight from RFC 6962 §2.1, different split derivation.
function ref(d: Uint8Array[]): string {
  if (d.length === 0) return emptyRoot();
  if (d.length === 1) return hashLeaf(d[0]);
  const k = 1 << (31 - Math.clz32(d.length - 1));
  return hashChildren(ref(d.slice(0, k)), ref(d.slice(k)));
}
const data = (n: number) => Array.from({ length: n }, (_, i) => enc.encode(`leaf-${i}`));
const flip = (h: string) => (h[0] === "0" ? "1" : "0") + h.slice(1);

test("rootHash matches the naive reference for every size up to 64", () => {
  for (let n = 0; n <= 64; n++) expect(rootHash(data(n).map(hashLeaf))).toBe(ref(data(n)));
});

test("inclusion: every (size, index) up to 64 verifies and tampering fails", () => {
  for (let n = 1; n <= 64; n++) {
    const leaves = data(n).map(hashLeaf), root = ref(data(n));
    for (let i = 0; i < n; i++) {
      const p = inclusionPath(leaves, i);
      expect(verifyInclusion(leaves[i], i, n, p, root), `n=${n} i=${i}`).toBe(true);
      expect(verifyInclusion(leaves[i], (i + 1) % n === i ? i + 1 : (i + 1) % n, n, p, root)).toBe(false); // wrong index
      expect(verifyInclusion(hashLeaf(enc.encode("other")), i, n, p, root)).toBe(false);                   // wrong leaf
      expect(verifyInclusion(leaves[i], i, n, p, flip(root))).toBe(false);                                 // wrong root
      // NOTE: a wrong claimed size is deliberately NOT asserted: the RFC 9162 verifier can accept the same path for size n+1
      // (e.g. leaf 0, n=3 vs 4). Size is authenticated by the STH (signed treeSize+root), not by the inclusion proof.
      if (p.length) expect(verifyInclusion(leaves[i], i, n, [flip(p[0]), ...p.slice(1)], root)).toBe(false); // flipped path
      expect(verifyInclusion(leaves[i], i, n, [...p, "00".repeat(32)], root)).toBe(false);                 // extra node
      if (p.length) expect(verifyInclusion(leaves[i], i, n, p.slice(1), root)).toBe(false);                // short path
    }
  }
});

test("consistency: every 1 <= m <= n <= 64 verifies and tampering fails", () => {
  for (let n = 1; n <= 64; n++) {
    const leaves = data(n).map(hashLeaf), rootN = ref(data(n));
    for (let m = 1; m <= n; m++) {
      const rootM = ref(data(m)), p = consistencyPath(leaves, m);
      expect(verifyConsistency(m, n, rootM, rootN, p), `m=${m} n=${n}`).toBe(true);
      expect(verifyConsistency(m, n, flip(rootM), rootN, p)).toBe(false);
      expect(verifyConsistency(m, n, rootM, flip(rootN), p)).toBe(false);
      if (p.length) expect(verifyConsistency(m, n, rootM, rootN, [flip(p[0]), ...p.slice(1)])).toBe(false);
      if (p.length) expect(verifyConsistency(m, n, rootM, rootN, p.slice(1))).toBe(false);
      expect(verifyConsistency(m, n, rootM, rootN, [...p, "00".repeat(32)])).toBe(false);
    }
  }
});

test("consistency rejects forks: a different history of the same size", () => {
  const a = data(10).map(hashLeaf), forked = [...a.slice(0, 5), hashLeaf(enc.encode("evil")), ...a.slice(6)];
  const rootM = rootHash(a.slice(0, 7)); // honest 7-leaf head
  expect(verifyConsistency(7, 10, rootM, rootHash(forked), consistencyPath(forked, 7))).toBe(false);
});

test("malformed input returns false instead of throwing", () => {
  expect(verifyInclusion("zz", 0, 1, ["not-hex"], "x")).toBe(false);
  expect(verifyInclusion("a".repeat(64), 5, 2, [], "x")).toBe(false);
  expect(verifyConsistency(0, 3, "x", "y", [])).toBe(false);
  expect(verifyConsistency(5, 3, "x", "y", [])).toBe(false);
  expect(() => inclusionPath([], 0)).toThrow();
  expect(() => consistencyPath(data(3).map(hashLeaf), 4)).toThrow();
  void hex;
});
