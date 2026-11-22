import type { ReleaseEntry } from "@uw/shared";

const LOG = process.env.LOG_URL ?? "http://localhost:4000";
const WITNESSES = (process.env.WITNESS_URLS ?? "http://localhost:4101,http://localhost:4102,http://localhost:4103").split(",");
export type Leaf = { idx: number; entry: ReleaseEntry; leafHash: string };

/** All leaves from log-server, or null when it is unreachable (callers must show that, not fake data). */
export async function getLeaves(): Promise<Leaf[] | null> {
  try { const r = await fetch(`${LOG}/entries`, { cache: "no-store", signal: AbortSignal.timeout(2000) }); return r.ok ? await r.json() : null; }
  catch { return null; }
}
export async function appendEntry(e: ReleaseEntry): Promise<boolean> {
  try { return (await fetch(`${LOG}/entries`, { method: "POST", body: JSON.stringify(e) })).ok; } catch { return false; }
}
export async function witnessesOnline(): Promise<number> {
  const up = await Promise.all(WITNESSES.map((w) => fetch(`${w}/health`, { cache: "no-store", signal: AbortSignal.timeout(1000) }).then((r) => r.ok).catch(() => false)));
  return up.filter(Boolean).length;
}
