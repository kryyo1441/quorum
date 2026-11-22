import { expect, test } from "vitest";
import { canonicalize } from "./canonical.js";
test("sorted keys, no whitespace, nested", () => {
  expect(canonicalize({ b: 1, a: [{ d: 2, c: "x" }], u: undefined })).toBe('{"a":[{"c":"x","d":2}],"b":1}');
});
