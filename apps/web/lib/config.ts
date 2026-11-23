import { devSecret, publicKeyOf } from "@uw/log-core";
import type { VerifyConfig } from "@uw/client-sdk";

/** What a browser verifier trusts. PINNED from env, never fetched from the log or witnesses it is checking. DEV=1 uses the PUBLIC dev keys (demos only).
 *  URLs here are what the BROWSER can reach (PUBLIC_*), not the docker-internal ones. */
export function publicVerifyConfig(p: Record<string, string | undefined> = process.env): VerifyConfig | { error: string } {
  const dev = p.DEV === "1", ids = ["w1", "w2", "w3"];
  const urls = (p.PUBLIC_WITNESS_URLS ?? "http://localhost:4101,http://localhost:4102,http://localhost:4103").split(",");
  try {
    const wk: Record<string, string> = p.WITNESS_PUBLIC_KEYS ? JSON.parse(p.WITNESS_PUBLIC_KEYS) : dev ? Object.fromEntries(ids.map((w) => [w, publicKeyOf(devSecret(`witness-${w}`))])) : {};
    const logPublicKey = p.LOG_PUBLIC_KEY ?? (dev ? publicKeyOf(devSecret("log")) : undefined);
    const vsk = p.VENDOR_SECRET_KEY ?? (dev ? devSecret("vendor") : undefined);
    const vendorPublicKeys: Record<string, string> = p.VENDOR_PUBLIC_KEYS ? JSON.parse(p.VENDOR_PUBLIC_KEYS) : vsk ? { [p.VENDOR_KEY_ID ?? "demo"]: publicKeyOf(vsk) } : {};
    if (!logPublicKey || !ids.every((w) => wk[w]) || !Object.keys(vendorPublicKeys).length) return { error: "verifier keys not configured: set LOG_PUBLIC_KEY, WITNESS_PUBLIC_KEYS and VENDOR_PUBLIC_KEYS (or DEV=1)" };
    return { logUrl: p.PUBLIC_LOG_URL ?? "http://localhost:4000", threshold: 2, maxAgeMs: 5 * 60_000, logPublicKey, vendorPublicKeys, witnesses: ids.map((id, i) => ({ id, url: urls[i], publicKey: wk[id] })) };
  } catch (e) { return { error: `bad verifier config: ${e instanceof Error ? e.message : e}` }; }
}
