import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { generateKeypair, publicKeyOf, signEntry } from "@uw/log-core";
import { ReleaseEntry, type ReleaseEntry as Entry } from "@uw/shared";

export type PublishOpts = { file: string; app: string; version: string; platform: Entry["platform"]; url: string; keyId: string; secretKey: string; logUrl: string };
export type Published = { entry: Entry; leafIndex: number; treeSize: number };

/** Hash the release file, sign the entry with the vendor key, append it to the log. Throws if the log refuses (a log only takes entries signed by a registered vendor key). */
export async function publish(o: PublishOpts, f: typeof fetch = fetch): Promise<Published> {
  const bytes = readFileSync(o.file);
  const entry = signEntry({ app: o.app, version: o.version, platform: o.platform, sha256: createHash("sha256").update(bytes).digest("hex"), size: bytes.length, url: o.url, publishedAt: new Date().toISOString(), vendorKeyId: o.keyId }, o.secretKey);
  ReleaseEntry.parse(entry); // refuse to send something the log would reject as malformed
  const r = await f(`${o.logUrl}/entries`, { method: "POST", body: JSON.stringify(entry) });
  if (!r.ok) throw new Error(`log refused the release: ${r.status} ${await r.text()}`);
  const b = (await r.json()) as { idx: number; sth: { treeSize: number } };
  return { entry, leafIndex: b.idx, treeSize: b.sth.treeSize };
}
export const keygen = () => { const k = generateKeypair(); return { secretKey: k.secretKey, publicKey: k.publicKey }; };
export { publicKeyOf };
