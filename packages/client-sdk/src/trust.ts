import { z } from "zod";
import type { VerifyConfig } from "./verify.js";

const b64 = z.string().regex(/^[A-Za-z0-9+/]{43}=$/, "must be a base64 32-byte Ed25519 key");
const Trust = z.object({
  logUrl: z.string().url(),
  logPublicKey: b64,
  witnesses: z.array(z.object({ id: z.string().min(1), url: z.string().url(), publicKey: b64 }).strict()).min(1),
  threshold: z.number().int().min(1),
  vendorPublicKeys: z.record(b64).refine((o) => Object.keys(o).length > 0, "at least one vendor key"),
  maxAgeMs: z.number().positive().finite().optional(),
  expected: z.object({ app: z.string().min(1), platform: z.string().min(1), installedVersion: z.string().optional() }).strict().optional(),
}).strict();

/** The TRUST BUNDLE an app ships with (baked in at build time, never fetched from the log or witnesses it will check): log key, witness keys, vendor keys, threshold.
 *  Strict: unknown fields, malformed keys, duplicate witnesses and an impossible threshold are errors, so a typo cannot silently weaken verification.
 *  Pass `expected` (this install's app/platform/current version) at run time to get downgrade protection. */
export function parseTrust(json: unknown, runtime: Pick<VerifyConfig, "expected"> = {}): VerifyConfig {
  const t = Trust.parse(json);
  if (t.threshold > t.witnesses.length) throw new Error(`threshold ${t.threshold} exceeds the ${t.witnesses.length} configured witnesses`);
  if (new Set(t.witnesses.map((w) => w.id)).size !== t.witnesses.length || new Set(t.witnesses.map((w) => w.publicKey)).size !== t.witnesses.length) throw new Error("duplicate witness id or key");
  return { ...t, expected: runtime.expected ?? t.expected };
}
