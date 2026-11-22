import { expect, test } from "vitest";
import { cosign, generateKeypair, leafHashOfEntry, publicKeyOf, signEntry, signSTH, verifyCosig, verifyEntry, verifyLogSig } from "./sign.js";

const unsigned = { app: "a", version: "1.0.0", platform: "win-x64" as const, sha256: "a".repeat(64), size: 3, url: "u", publishedAt: "2026-01-01T00:00:00.000Z", vendorKeyId: "v1" };
const body = { logId: "log1", treeSize: 8, rootHash: "b".repeat(64), timestamp: "2026-01-01T00:00:00.000Z" };

test("vendor signature verifies, and any field change or wrong key fails", () => {
  const v = generateKeypair(), other = generateKeypair();
  const e = signEntry(unsigned, v.secretKey);
  expect(verifyEntry(e, v.publicKey)).toBe(true);
  expect(publicKeyOf(v.secretKey)).toBe(v.publicKey);
  expect(verifyEntry({ ...e, sha256: "c".repeat(64) }, v.publicKey)).toBe(false);
  expect(verifyEntry({ ...e, version: "1.0.1" }, v.publicKey)).toBe(false);
  expect(verifyEntry(e, other.publicKey)).toBe(false);
  expect(verifyEntry({ ...e, vendorSig: "!!notbase64" }, v.publicKey)).toBe(false);
});

test("leaf hash covers the whole entry including the signature", () => {
  const v = generateKeypair(), e = signEntry(unsigned, v.secretKey);
  expect(leafHashOfEntry(e)).toMatch(/^[0-9a-f]{64}$/);
  expect(leafHashOfEntry({ ...e, vendorSig: "x" })).not.toBe(leafHashOfEntry(e));
});

test("STH log signature binds every field", () => {
  const log = generateKeypair(), sth = signSTH(body, log.secretKey);
  expect(verifyLogSig(sth, log.publicKey)).toBe(true);
  for (const t of [{ treeSize: 9 }, { rootHash: "c".repeat(64) }, { timestamp: "2026-01-02T00:00:00.000Z" }, { logId: "log2" }])
    expect(verifyLogSig({ ...sth, ...t }, log.publicKey)).toBe(false);
  expect(verifyLogSig(sth, generateKeypair().publicKey)).toBe(false);
});

test("cosig binds witness id, cosig timestamp and the head, and is not a log signature", () => {
  const w = generateKeypair(), sth = signSTH(body, generateKeypair().secretKey);
  const c = cosign(sth, "w1", w.secretKey, "2026-01-01T00:01:00.000Z");
  expect(verifyCosig(sth, c, w.publicKey)).toBe(true);
  expect(verifyCosig(sth, { ...c, witnessId: "w2" }, w.publicKey)).toBe(false);
  expect(verifyCosig(sth, { ...c, timestamp: "2026-01-01T00:02:00.000Z" }, w.publicKey)).toBe(false);
  expect(verifyCosig({ ...sth, rootHash: "c".repeat(64) }, c, w.publicKey)).toBe(false);
  expect(verifyLogSig({ ...sth, logSig: c.sig }, w.publicKey)).toBe(false); // domain separation
});

// ---- added after the independent review ----
import { devSecret } from "./sign.js";
const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

test("signatures and keys have exactly one accepted spelling", () => {
  const v = generateKeypair(), e = signEntry(unsigned, v.secretKey), sig = e.vendorSig;
  expect(sig.endsWith("==")).toBe(true); // 64 bytes -> padded; stripping padding must not verify
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", ti = A.indexOf(sig.at(-3)!); // last data char: 4 data bits + 2 unused bits
  const trailing = (x: number) => sig.slice(0, -3) + A[ti ^ x] + "==";
  for (const bad of [sig.slice(0, -2), " " + sig, sig + "\n", trailing(1), trailing(2), trailing(3)])
    expect(verifyEntry({ ...e, vendorSig: bad }, v.publicKey), JSON.stringify(bad)).toBe(false);
  expect(verifyEntry(e, " " + v.publicKey)).toBe(false);
  expect(verifyEntry(e, v.publicKey.slice(0, -1))).toBe(false);
  expect(verifyEntry({ ...e, vendorSig: b64(unb64(sig).slice(0, 63)) }, v.publicKey)).toBe(false);
});

test("small-order public keys never verify (identity key + zero signature would pass under ZIP-215)", () => {
  const identity = new Uint8Array(32); identity[0] = 1;                       // the neutral point
  const sig = new Uint8Array(64); sig[0] = 1;                                  // R = identity, S = 0
  expect(verifyEntry({ ...signEntry(unsigned, generateKeypair().secretKey), vendorSig: b64(sig) }, b64(identity))).toBe(false);
});

test("devSecret is deterministic, purpose-separated, and a valid key", () => {
  expect(devSecret("log")).toBe(devSecret("log"));
  expect(devSecret("log")).not.toBe(devSecret("vendor"));
  expect(publicKeyOf(devSecret("log"))).toMatch(/^[A-Za-z0-9+/]{43}=$/);
});
