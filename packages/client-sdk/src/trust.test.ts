import { generateKeypair } from "@uw/log-core";
import { expect, test } from "vitest";
import { parseTrust } from "./trust.js";

const k = () => generateKeypair().publicKey;
const good = () => ({ logUrl: "https://log.example", logPublicKey: k(), threshold: 2, vendorPublicKeys: { v1: k() }, approverPublicKey: k(), witnesses: ["w1", "w2", "w3"].map((id) => ({ id, url: `https://${id}.example`, publicKey: k() })) });

test("a well-formed bundle loads, and `expected` can be supplied at run time", () => {
  const c = parseTrust(good(), { expected: { app: "a", platform: "win-x64", installedVersion: "1.0.0" } });
  expect(c.witnesses).toHaveLength(3);
  expect(c.expected?.installedVersion).toBe("1.0.0");
});
test("anything that could silently weaken verification is rejected", () => {
  for (const bad of [
    { ...good(), threshold: 4 }, { ...good(), threshold: 0 }, { ...good(), threshold: 1.5 },
    { ...good(), logPublicKey: "nope" }, { ...good(), vendorPublicKeys: {} }, { ...good(), extra: 1 },
    { ...good(), witnesses: [] }, { ...good(), maxAgeMs: -1 }, { ...good(), logUrl: "not a url" },
    (() => { const g = good(); g.witnesses[1].id = "w1"; return g; })(),
    (() => { const g = good(); g.witnesses[1].publicKey = g.witnesses[0].publicKey; return g; })(),
  ]) expect(() => parseTrust(bad)).toThrow();
});
test("the approver key is mandatory and must not be a vendor key (one key must not do both jobs)", () => {
  const { approverPublicKey: _a, ...none } = good();
  expect(() => parseTrust(none)).toThrow();
  const g = good(); g.approverPublicKey = g.vendorPublicKeys.v1;
  expect(() => parseTrust(g)).toThrow(/differ/);
});
