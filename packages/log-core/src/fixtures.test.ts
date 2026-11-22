import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { build } from "../../../fixtures/generate.js";
import { consistencyPath, inclusionPath, rootHash, verifyConsistency, verifyCosig, verifyEntry, verifyInclusion, verifyLogSig } from "./index.js";

const committed = JSON.parse(readFileSync(new URL("../../../fixtures/vectors.json", import.meta.url), "utf8"));

test("committed vectors.json equals a fresh regeneration (deterministic)", () => {
  expect(JSON.parse(JSON.stringify(build()))).toEqual(committed);
});

test("valid vectors verify, tampered vectors are rejected", () => {
  const v = committed, k = v.keys;
  expect(rootHash(v.leaves)).toBe(v.sth.rootHash);
  expect(verifyLogSig(v.sth, k.log.publicKey)).toBe(true);
  for (const c of v.sth.cosigs) expect(verifyCosig(v.sth, c, k[c.witnessId].publicKey)).toBe(true);
  v.entries.forEach((e: any, i: number) => {
    expect(verifyEntry(e, k.vendor.publicKey)).toBe(true);
    expect(verifyInclusion(v.leaves[i], i, 16, v.inclusion[i].path, v.sth.rootHash)).toBe(true);
    expect(v.inclusion[i].path).toEqual(inclusionPath(v.leaves, i));
  });
  for (const c of v.consistency) {
    expect(verifyConsistency(c.fromSize, 16, c.fromRoot, v.sth.rootHash, c.path)).toBe(true);
    expect(c.path).toEqual(consistencyPath(v.leaves, c.fromSize));
  }
  const t = v.tampered;
  expect(verifyEntry(t.entryHashChanged, k.vendor.publicKey)).toBe(false);
  expect(verifyEntry(t.entryBadVendorSig, k.vendor.publicKey)).toBe(false);
  expect(verifyInclusion(v.leaves[5], 5, 16, t.inclusionPathFlipped.path, v.sth.rootHash)).toBe(false);
  expect(verifyInclusion(v.leaves[5], t.inclusionWrongIndex.leafIndex, 16, t.inclusionWrongIndex.path, v.sth.rootHash)).toBe(false);
  expect(verifyLogSig(t.sthRootChanged, k.log.publicKey)).toBe(false);
  expect(verifyLogSig(t.sthBadLogSig, k.log.publicKey)).toBe(false);
  expect(verifyCosig(t.sthOneCosigBad, t.sthOneCosigBad.cosigs[0], k.w1.publicKey)).toBe(false);
  expect(verifyCosig(t.sthCosigWrongWitness, t.sthCosigWrongWitness.cosigs[0], k.w1.publicKey)).toBe(false);
  expect(verifyConsistency(5, 16, t.consistencyPathFlipped.fromRoot, v.sth.rootHash, t.consistencyPathFlipped.path)).toBe(false);
});
