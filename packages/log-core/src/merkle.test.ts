import { expect, test } from "vitest";
import { CompactTree, consistencyPath, emptyRoot, hashChildren, hashLeaf, hashNode, inclusionPath, rootHash, verifyConsistency, verifyInclusion } from "./merkle.js";

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

// ---- added after the independent review ----
const hx = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (b) => parseInt(b, 16));
// Reference leaves/roots for sizes 1..8 from the Certificate Transparency / transparency-dev test data.
// Source note: recalled by two independent reviewers and reproduced by this implementation; not fetched verbatim from the repo.
const CT_LEAVES = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"].map(hx);
const CT_ROOTS = ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
  "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77", "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
  "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4", "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
  "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c", "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"];

test("hashNode matches the published N123/N456 vector (guards prefix byte and argument order)", () => {
  expect(hashNode(enc.encode("N123"), enc.encode("N456"))).toBe("aa217fe888e47007fa15edab33c2b492a722cb106c64667fc2b044444de66bbb");
  expect(hashNode(enc.encode("N456"), enc.encode("N123"))).not.toBe("aa217fe888e47007fa15edab33c2b492a722cb106c64667fc2b044444de66bbb");
});
test("roots of the standard 8 CT leaves for sizes 1..8", () => {
  const L = CT_LEAVES.map(hashLeaf);
  for (let n = 1; n <= 8; n++) expect(rootHash(L.slice(0, n)), `size ${n}`).toBe(CT_ROOTS[n - 1]);
  for (let n = 1; n <= 8; n++) for (let m = 1; m <= n; m++)
    expect(verifyConsistency(m, n, CT_ROOTS[m - 1], CT_ROOTS[n - 1], consistencyPath(L.slice(0, n), m))).toBe(true);
});
test("CompactTree root equals rootHash at every size", () => {
  const L = data(70).map(hashLeaf), t = new CompactTree();
  expect(t.root()).toBe(emptyRoot());
  for (let n = 1; n <= 70; n++) { t.append(L[n - 1]); expect(t.root(), `n=${n}`).toBe(rootHash(L.slice(0, n))); expect(t.size).toBe(n); }
  expect(new CompactTree(L.slice(0, 33)).root()).toBe(rootHash(L.slice(0, 33)));
});
test("forks: a rewritten past leaf never yields a proof that verifies against the honest old root", () => {
  for (let n = 2; n <= 24; n++) {
    const honest = data(n).map(hashLeaf);
    for (let m = 1; m < n; m++) {
      const rootM = rootHash(honest.slice(0, m));
      for (let i = 0; i < m; i++) {
        const forked = honest.map((h, j) => (j === i ? hashLeaf(enc.encode("evil")) : h));
        expect(verifyConsistency(m, n, rootM, rootHash(forked), consistencyPath(forked, m)), `n=${n} m=${m} fork@${i}`).toBe(false);
      }
    }
  }
});
test("large sizes: split and power-of-two detection are exact", () => {
  const big = 2 ** 49, m = 2 ** 32 + 2 ** 31;
  // m is NOT a power of two: a 32-bit truncating test would wrongly say it is, and prepend rootM to the path
  const r = (n: number) => `${n}`.padStart(64, "0");
  expect(verifyConsistency(m, big, r(1), r(2), [r(3)])).toBe(false); // must simply reject, never throw or loop
  expect(() => verifyInclusion(r(1), 0, big, Array(49).fill(r(2)), r(3))).not.toThrow();
});
test("strict hash shapes: uppercase, odd lengths and non-strings are rejected", () => {
  const L = data(3).map(hashLeaf), root = rootHash(L), p = inclusionPath(L, 2);
  expect(verifyInclusion(L[2], 2, 3, p, root)).toBe(true);
  expect(verifyInclusion(L[2], 2, 3, p.map((x) => x.toUpperCase()), root)).toBe(false);
  expect(verifyInclusion(L[2], 2, 3, [p[0].slice(2), ...p.slice(1)], root)).toBe(false);
  expect(verifyInclusion(L[2].toUpperCase(), 2, 3, p, root)).toBe(false);
  expect(verifyInclusion(L[2], 2, 3, p, root.toUpperCase())).toBe(false);
  expect(verifyInclusion(L[2], 2, 3, [1 as any, 2 as any], root)).toBe(false);
  expect(verifyInclusion(L[2], 1.5, 3, p, root)).toBe(false);
  expect(() => inclusionPath(L, NaN)).toThrow();
});
