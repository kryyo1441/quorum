import { devSecret, generateKeypair, publicKeyOf, signSTH } from "@uw/log-core";
import type { STH } from "@uw/shared";

export type LogIdentity = { logId: string; secretKey: string; publicKey: string };
const isDev = (env: Record<string, string | undefined>) => env.DEV === "1";

/** Log identity from env. LOG_SECRET_KEY is REQUIRED; only with DEV=1 may the public dev key be used (anyone can derive it and forge heads). */
export function logIdentity(env: Record<string, string | undefined> = process.env): LogIdentity {
  const logId = env.LOG_ID ?? "uw-dev-log";
  let secretKey = env.LOG_SECRET_KEY;
  if (!secretKey) {
    if (!isDev(env)) throw new Error("LOG_SECRET_KEY is required (set DEV=1 only for demos: it uses a public key)");
    console.warn("DEV=1: signing heads with the PUBLIC dev key. Never do this outside a demo.");
    secretKey = devSecret("log");
  }
  return { logId, secretKey, publicKey: publicKeyOf(secretKey) };
}

/** Registered vendor keys the log accepts entries from: VENDOR_PUBLIC_KEYS='{"keyId":"<base64 pub>"}'. Required unless DEV=1 (then the public dev vendor key "demo"). */
export function vendorKeys(env: Record<string, string | undefined> = process.env): Record<string, string> {
  if (env.VENDOR_PUBLIC_KEYS) {
    const k = JSON.parse(env.VENDOR_PUBLIC_KEYS);
    if (!k || typeof k !== "object" || Array.isArray(k) || !Object.values(k).every((v) => typeof v === "string")) throw new Error("VENDOR_PUBLIC_KEYS must be a JSON object of keyId -> base64 public key");
    return Object.assign(Object.create(null), k);
  }
  if (!isDev(env)) throw new Error("VENDOR_PUBLIC_KEYS is required (set DEV=1 only for demos)");
  return { demo: publicKeyOf(devSecret("vendor")) };
}

export const newIdentity = (logId = "test-log"): LogIdentity => ({ logId, ...generateKeypair() });

/** Sign the head for a tree of `size` leaves with root `rootHash`. Cosigs are attached later by witnesses. */
export const signHead = (id: LogIdentity, size: number, rootHash: string, now = new Date()): STH =>
  signSTH({ logId: id.logId, treeSize: size, rootHash, timestamp: now.toISOString() }, id.secretKey);
