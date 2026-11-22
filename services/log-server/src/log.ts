import { generateKeypair, publicKeyOf, rootHash, signSTH } from "@uw/log-core";
import type { STH } from "@uw/shared";
import { createHash } from "node:crypto";

export type LogIdentity = { logId: string; secretKey: string; publicKey: string };

/** Log identity from env. Without LOG_SECRET_KEY a fixed PUBLIC dev key is used so restarts keep verifying old heads. */
export function logIdentity(env = process.env): LogIdentity {
  const logId = env.LOG_ID ?? "uw-dev-log";
  let secretKey = env.LOG_SECRET_KEY;
  if (!secretKey) {
    console.warn("LOG_SECRET_KEY not set: using the public dev key. Never do this outside a demo.");
    secretKey = btoa(String.fromCharCode(...createHash("sha256").update("uw-dev-log-key").digest()));
  }
  return { logId, secretKey, publicKey: publicKeyOf(secretKey) };
}
export const newIdentity = (logId = "test-log"): LogIdentity => ({ logId, ...generateKeypair() });

/** Sign the head for the first `size` leaves. Cosigs are attached later by witnesses. */
export const headFor = (id: LogIdentity, leafHashes: string[], size: number, now = new Date()): STH =>
  signSTH({ logId: id.logId, treeSize: size, rootHash: rootHash(leafHashes.slice(0, size)), timestamp: now.toISOString() }, id.secretKey);
