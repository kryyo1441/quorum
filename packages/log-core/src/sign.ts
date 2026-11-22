// Ed25519 signing payloads (defined ONCE here; see fixtures/README) and sign/verify helpers.
// Keys and signatures are base64. Browser-safe.
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { canonicalBytes, type ReleaseEntry, type STH } from "@uw/shared";
import { hashLeaf } from "./merkle.js";

ed.hashes.sha512 = sha512; // enables the sync API

const enc = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const dec = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export type Unsigned<T, K extends keyof T> = Omit<T, K>;
export type STHBody = Pick<STH, "logId" | "treeSize" | "rootHash" | "timestamp">;
export type Cosig = STH["cosigs"][number];

// ---- payloads: exactly what gets signed ----
export const entryPayload = (e: Unsigned<ReleaseEntry, "vendorSig">) => canonicalBytes(e);
export const sthPayload = (s: STHBody) => canonicalBytes({ logId: s.logId, rootHash: s.rootHash, timestamp: s.timestamp, treeSize: s.treeSize });
/** Cosig also binds the witness id and the cosig timestamp, with a domain-separation tag so it can never be replayed as a log signature. */
export const cosigPayload = (s: STHBody, witnessId: string, timestamp: string) =>
  canonicalBytes({ kind: "cosig", logId: s.logId, rootHash: s.rootHash, timestamp: s.timestamp, treeSize: s.treeSize, witnessId, cosigTimestamp: timestamp });

/** Leaf hash of a full ReleaseEntry (including vendorSig): SHA256(0x00 || canonical(entry)). */
export const leafHashOfEntry = (e: ReleaseEntry) => hashLeaf(canonicalBytes(e));

export function generateKeypair() { const k = ed.keygen(); return { secretKey: enc(k.secretKey), publicKey: enc(k.publicKey) }; }
export const publicKeyOf = (secretKey: string) => enc(ed.getPublicKey(dec(secretKey)));
const sign = (msg: Uint8Array, secretKey: string) => enc(ed.sign(msg, dec(secretKey)));
const verify = (sig: string, msg: Uint8Array, pub: string) => { try { return ed.verify(dec(sig), msg, dec(pub)); } catch { return false; } };

export const signEntry = (e: Unsigned<ReleaseEntry, "vendorSig">, vendorSecret: string): ReleaseEntry => ({ ...e, vendorSig: sign(entryPayload(e), vendorSecret) });
export const verifyEntry = (e: ReleaseEntry, vendorPublic: string) => { const { vendorSig, ...rest } = e; return verify(vendorSig, entryPayload(rest), vendorPublic); };

export const signSTH = (b: STHBody, logSecret: string): STH => ({ ...b, logSig: sign(sthPayload(b), logSecret), cosigs: [] });
export const verifyLogSig = (s: STH, logPublic: string) => verify(s.logSig, sthPayload(s), logPublic);

export const cosign = (s: STHBody, witnessId: string, witnessSecret: string, timestamp: string): Cosig =>
  ({ witnessId, timestamp, sig: sign(cosigPayload(s, witnessId, timestamp), witnessSecret) });
export const verifyCosig = (s: STHBody, c: Cosig, witnessPublic: string) => verify(c.sig, cosigPayload(s, c.witnessId, c.timestamp), witnessPublic);
