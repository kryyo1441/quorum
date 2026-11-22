import { z } from "zod";
// Wire formats frozen by SPEC §6. Do not change without human approval.
export const Platform = z.enum(["win-x64", "mac-arm64", "linux-x64"]);
export const ReleaseEntry = z.object({
  app: z.string(), version: z.string(), platform: Platform,
  sha256: z.string().regex(/^[0-9a-f]{64}$/), size: z.number().int().nonnegative(),
  url: z.string(), publishedAt: z.string().datetime(),
  vendorKeyId: z.string(), vendorSig: z.string(),
}).strict(); // strict: unknown fields are rejected, never silently stripped (a stripped entry would no longer match its vendorSig)
export const Cosig = z.object({ witnessId: z.string(), sig: z.string(), timestamp: z.string() });
export const STH = z.object({
  logId: z.string(), treeSize: z.number().int().nonnegative(), rootHash: z.string(),
  timestamp: z.string(), logSig: z.string(), cosigs: z.array(Cosig),
});
export const InclusionProof = z.object({ leafIndex: z.number().int(), treeSize: z.number().int(), path: z.array(z.string()) });
export const ConsistencyProof = z.object({ fromSize: z.number().int(), toSize: z.number().int(), path: z.array(z.string()) });
export const Observation = z.object({
  app: z.string(), version: z.string(), platform: z.string(), sha256: z.string(),
  sthRoot: z.string(), sthSize: z.number().int(), clientPseudonym: z.string(), observedAt: z.string(),
});
export const AlertKind = z.enum(["HASH_MISMATCH", "INCONSISTENT_STH", "NOT_IN_LOG", "UNAPPROVED_RELEASE"]);
export const SplitViewAlert = z.object({
  kind: AlertKind, app: z.string(), version: z.string(), platform: z.string(),
  evidence: z.record(z.unknown()), raisedBy: z.string(), raisedAt: z.string(),
});
export const FailReason = z.enum(["HASH_MISMATCH", "NOT_IN_LOG", "BAD_INCLUSION_PROOF", "BAD_VENDOR_SIG", "INSUFFICIENT_COSIGS", "STALE_STH", "SPLIT_VIEW"]);

export type ReleaseEntry = z.infer<typeof ReleaseEntry>;
export type STH = z.infer<typeof STH>;
export type InclusionProof = z.infer<typeof InclusionProof>;
export type ConsistencyProof = z.infer<typeof ConsistencyProof>;
export type Observation = z.infer<typeof Observation>;
export type SplitViewAlert = z.infer<typeof SplitViewAlert>;
export type FailReason = z.infer<typeof FailReason>;
