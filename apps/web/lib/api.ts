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

export type Head = import("@uw/shared").STH;
export async function getHeads(): Promise<Head[] | null> {
  try { const r = await fetch(`${LOG}/sths`, { cache: "no-store", signal: AbortSignal.timeout(2000) }); return r.ok ? await r.json() : null; } catch { return null; }
}
export async function getLogKey(): Promise<string | null> {
  try { const r = await fetch(`${LOG}/key`, { cache: "no-store", signal: AbortSignal.timeout(2000) }); return r.ok ? (await r.json()).publicKey : null; } catch { return null; }
}
/** Untrusted proof from the log; the browser verifies it, we only relay. */
export async function getProof(idx: number, treeSize: number): Promise<string[] | null> {
  try { const r = await fetch(`${LOG}/entries/${idx}/proof?treeSize=${treeSize}`, { cache: "no-store", signal: AbortSignal.timeout(2000) }); return r.ok ? (await r.json()).path : null; } catch { return null; }
}

const MONITOR = process.env.MONITOR_URL ?? "http://localhost:4300";
export type Alert = { kind: string; app: string; version: string; platform: string; raisedBy: string; raisedAt: string; evidence: Record<string, unknown> };
export type WitnessStatus = { id: string; online: boolean; head: Head | null; alerts: Alert[] };
const j = async <T>(url: string): Promise<T | null> => { try { const r = await fetch(url, { cache: "no-store", signal: AbortSignal.timeout(1500) }); return r.ok ? ((await r.json()) as T) : null; } catch { return null; } };

/** Each witness's own view: reachable?, its last cosigned head, its alerts. Unreachable is reported as offline, never guessed. */
export async function getWitnesses(): Promise<WitnessStatus[]> {
  return Promise.all(WITNESSES.map(async (url, i) => {
    const health = await j<{ id: string }>(`${url}/health`);
    return { id: health?.id ?? `w${i + 1}`, online: !!health, head: health ? await j<Head>(`${url}/sth`) : null, alerts: health ? (await j<Alert[]>(`${url}/alerts`)) ?? [] : [] };
  }));
}
export async function getMonitorAlerts(): Promise<Alert[] | null> { return j<Alert[]>(`${MONITOR}/alerts`); }

/** Adds a release to the monitor's approved list. Uses MONITOR_TOKEN (a credential separate from the release key; DEV=1 only: the public dev token). */
export async function approveRelease(e: ReleaseEntry): Promise<boolean> {
  const token = process.env.MONITOR_TOKEN ?? (process.env.DEV === "1" ? "dev-monitor-token" : undefined);
  if (!token) return false;
  try { return (await fetch(`${MONITOR}/approved`, { method: "POST", headers: { authorization: `Bearer ${token}` }, body: JSON.stringify({ app: e.app, version: e.version, platform: e.platform, sha256: e.sha256 }), signal: AbortSignal.timeout(2000) })).ok; } catch { return false; }
}
