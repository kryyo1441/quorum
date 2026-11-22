import { createHash } from "node:crypto";
import { canonicalBytes, type ConsistencyProof, type InclusionProof, type ReleaseEntry, type STH } from "@uw/shared";

/** The seam between this service (Sonnet) and packages/log-core (Opus, SPEC §4/§6).
 *  Replace `stubCore` with an implementation over log-core; routes don't change. */
export interface LogCore {
  leafHash(entry: ReleaseEntry): string;
  sth(leafHashes: string[]): STH | undefined;
  inclusionProof(leafHashes: string[], idx: number): InclusionProof;
  consistencyProof(leafHashes: string[], from: number, to: number): ConsistencyProof;
}

export class NotImplemented extends Error {}
const todo = (what: string): never => { throw new NotImplemented(`${what}: needs packages/log-core`); };

/** STUB: only the leaf hash, which is defined in SPEC §6 (SHA256(0x00 || canonical(entry))).
 *  ponytail: Codex should review this against RFC 6962 vectors. No tree root, STH signing or proofs here. */
export const stubCore: LogCore = {
  leafHash: (e) => createHash("sha256").update(Buffer.concat([Buffer.from([0]), canonicalBytes(e)])).digest("hex"),
  sth: () => undefined,
  inclusionProof: () => todo("inclusion proof"),
  consistencyProof: () => todo("consistency proof"),
};
