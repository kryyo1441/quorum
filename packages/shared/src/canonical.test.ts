import { expect, test } from "vitest";
import { canonicalize } from "./canonical.js";
test("sorted keys, no whitespace, nested", () => {
  expect(canonicalize({ b: 1, a: [{ d: 2, c: "x" }], u: undefined })).toBe('{"a":[{"c":"x","d":2}],"b":1}');
});

import { ReleaseEntry } from "./schemas.js";
test("ReleaseEntry rejects unknown fields instead of stripping them", () => {
  const e = { app: "a", version: "1.0.0", platform: "win-x64", sha256: "a".repeat(64), size: 1, url: "u", publishedAt: "2026-01-01T00:00:00.000Z", vendorKeyId: "k", vendorSig: "s" };
  expect(ReleaseEntry.safeParse(e).success).toBe(true);
  expect(ReleaseEntry.safeParse({ ...e, extra: 1 }).success).toBe(false);
});
