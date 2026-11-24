import { devSecret, publicKeyOf } from "@uw/log-core";
import type { Env } from "./fleet.js";

/** Config for talking to a RUNNING stack. DEV=1 fills in the PUBLIC dev keys (demos only); otherwise every key must be given. */
export function envFromProcess(p: Record<string, string | undefined> = process.env): Env {
  const dev = p.DEV === "1";
  const need = (k: string) => { const v = p[k]; if (!v) throw new Error(`${k} is required (or DEV=1 for the public dev keys)`); return v; };
  const ids = ["w1", "w2", "w3"], urls = (p.WITNESS_URLS ?? "http://localhost:4101,http://localhost:4102,http://localhost:4103").split(",");
  const wkeys: Record<string, string> = p.WITNESS_PUBLIC_KEYS ? JSON.parse(p.WITNESS_PUBLIC_KEYS) : dev ? Object.fromEntries(ids.map((w) => [w, publicKeyOf(devSecret(`witness-${w}`))])) : need("WITNESS_PUBLIC_KEYS") as never;
  const vendorSecret = p.VENDOR_SECRET_KEY ?? (dev ? devSecret("vendor") : need("VENDOR_SECRET_KEY"));
  const keyId = p.VENDOR_KEY_ID ?? "demo";
  const approverSecret = p.APPROVER_SECRET_KEY ?? (dev ? devSecret("approver") : need("APPROVER_SECRET_KEY"));
  return {
    vendor: { keyId, secretKey: vendorSecret },
    approver: { secretKey: approverSecret },
    updateUrl: p.UPDATE_URL ?? "http://localhost:4001",
    logUrl: p.LOG_URL ?? "http://localhost:4000",
    monitor: { url: p.MONITOR_URL ?? "http://localhost:4300", token: p.MONITOR_TOKEN ?? (dev ? "dev-monitor-token" : need("MONITOR_TOKEN")) },
    verify: {
      logUrl: p.LOG_URL ?? "http://localhost:4000", threshold: Number(p.THRESHOLD ?? 2), maxAgeMs: Number(p.MAX_AGE_MS ?? 5 * 60 * 1000),
      logPublicKey: p.LOG_PUBLIC_KEY ?? (dev ? publicKeyOf(devSecret("log")) : need("LOG_PUBLIC_KEY")),
      approverPublicKey: p.APPROVER_PUBLIC_KEY ?? publicKeyOf(approverSecret),
      vendorPublicKeys: p.VENDOR_PUBLIC_KEYS ? JSON.parse(p.VENDOR_PUBLIC_KEYS) : { [keyId]: publicKeyOf(vendorSecret) },
      witnesses: ids.map((id, i) => ({ id, url: urls[i], publicKey: wkeys[id] })),
    },
    fetch,
  };
}
