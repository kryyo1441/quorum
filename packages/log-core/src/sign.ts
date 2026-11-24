// Ed25519 signing payloads (defined ONCE here; see fixtures/README) and sign/verify helpers.
// Keys and signatures are base64. Browser-safe.
import * as ed from "@noble/ed25519";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { canonicalBytes, type ReleaseEntry, type STH } from "@uw/shared";
import { hashLeaf } from "./merkle.js";

ed.hashes.sha512 = sha512; // enables the sync API

const enc = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
/** Strict base64: canonical form only (no whitespace, no stripped padding, no stray trailing bits) and an exact byte length.
 *  Prevents one signature or key from having several accepted spellings. Throws on anything else. */
function dec(s: string, len: number): Uint8Array {
  if (typeof s !== "string" || !B64.test(s) || s.length % 4 !== 0) throw new Error("bad base64");
  const b = Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  if (enc(b) !== s || b.length !== len) throw new Error("non-canonical or wrong-length base64");
  return b;
}

/** Deterministic PUBLIC dev/test secret key for a purpose ("log", "vendor", ...). Never use outside demos and tests. */
export const devSecret = (purpose: string) => enc(sha256(new TextEncoder().encode(`uw-dev-key/${purpose}`)));

export type Unsigned<T, K extends keyof T> = Omit<T, K>;
type Body = Omit<ReleaseEntry, "vendorSig" | "approverSig">;
export type STHBody = Pick<STH, "logId" | "treeSize" | "rootHash" | "timestamp">;
export type Cosig = STH["cosigs"][number];

// ---- payloads: exactly what gets signed ----
export const entryPayload = (e: Body) => canonicalBytes(e);
/** The approver signs the vendor-signed entry under a domain tag, so a vendor signature can never be replayed as an approval (and vice versa). */
export const approvalPayload = (e: Omit<ReleaseEntry, "approverSig">) => canonicalBytes({ kind: "approve", ...e });
export const sthPayload = (s: STHBody) => canonicalBytes({ logId: s.logId, rootHash: s.rootHash, timestamp: s.timestamp, treeSize: s.treeSize });
/** Cosig also binds the witness id and the cosig timestamp, with a domain-separation tag so it can never be replayed as a log signature. */
export const cosigPayload = (s: STHBody, witnessId: string, timestamp: string) =>
  canonicalBytes({ kind: "cosig", logId: s.logId, rootHash: s.rootHash, timestamp: s.timestamp, treeSize: s.treeSize, witnessId, cosigTimestamp: timestamp });

/** Leaf hash of a full ReleaseEntry (including vendorSig): SHA256(0x00 || canonical(entry)). */
export const leafHashOfEntry = (e: ReleaseEntry) => hashLeaf(canonicalBytes(e));

export function generateKeypair() { const k = ed.keygen(); return { secretKey: enc(k.secretKey), publicKey: enc(k.publicKey) }; }
export const publicKeyOf = (secretKey: string) => enc(ed.getPublicKey(dec(secretKey, 32)));
const sign = (msg: Uint8Array, secretKey: string) => enc(ed.sign(msg, dec(secretKey, 32)));
/** Strict RFC 8032 verification (zip215:false), and small-order public keys are rejected (the identity key would verify any message under ZIP215). */
const verify = (sig: string, msg: Uint8Array, pub: string) => {
  try {
    const p = dec(pub, 32), s = dec(sig, 64);
    if (ed.Point.fromBytes(p, false).isSmallOrder()) return false;
    return ed.verify(s, msg, p, { zip215: false });
  } catch { return false; }
};

export const signEntry = (e: Body, vendorSecret: string): ReleaseEntry => ({ ...e, vendorSig: sign(entryPayload(e), vendorSecret) });
/** Vendor signature only (the approval is checked separately, see verifyApproval). */
export const verifyEntry = (e: ReleaseEntry, vendorPublic: string) => { const { vendorSig, approverSig: _a, ...rest } = e; return verify(vendorSig, entryPayload(rest), vendorPublic); };
/** Second signature, by a SEPARATE key: stealing the release key alone cannot log a release. */
export const approveEntry = (e: ReleaseEntry, approverSecret: string): ReleaseEntry => { const { approverSig: _a, ...rest } = e; return { ...rest, approverSig: sign(approvalPayload(rest), approverSecret) }; };
export const verifyApproval = (e: ReleaseEntry, approverPublic: string) => { const { approverSig, ...rest } = e; return approverSig !== undefined && verify(approverSig, approvalPayload(rest), approverPublic); };

export const signSTH = (b: STHBody, logSecret: string): STH => ({ ...b, logSig: sign(sthPayload(b), logSecret), cosigs: [] });
export const verifyLogSig = (s: STH, logPublic: string) => verify(s.logSig, sthPayload(s), logPublic);

export const cosign = (s: STHBody, witnessId: string, witnessSecret: string, timestamp: string): Cosig =>
  ({ witnessId, timestamp, sig: sign(cosigPayload(s, witnessId, timestamp), witnessSecret) });
export const verifyCosig = (s: STHBody, c: Cosig, witnessPublic: string) => verify(c.sig, cosigPayload(s, c.witnessId, c.timestamp), witnessPublic);
