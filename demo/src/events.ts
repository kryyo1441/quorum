// One live feed for the dashboard (Server-Sent Events). The bus WATCHES the real services (log, witnesses, monitor) and records what the demo server itself does
// (client results, armed attacks). Watching means diffing what the services report, so nothing here can invent an event.
import type { Env } from "./fleet.js";

export type Ev = { id: number; at: string; type: "release" | "head" | "cosigned" | "alert" | "client" | "attack"; text: string; tone: "ok" | "bad" | "mute"; data?: unknown };

export function eventBus(env: Env, keep = 200) {
  const buf: Ev[] = [], subs = new Set<(e: Ev) => void>();
  const stats = { clientsVerified: 0, clientsBlocked: 0, alerts: 0, attacks: 0 };
  let seq = 0;
  const seen = { leaves: 0, heads: new Set<number>(), cosigned: new Set<number>(), alerts: new Set<string>() };
  const emit = (type: Ev["type"], text: string, tone: Ev["tone"], data?: unknown) => {
    const e: Ev = { id: ++seq, at: new Date().toISOString(), type, text, tone, data };
    buf.push(e); if (buf.length > keep) buf.shift();
    for (const s of subs) s(e);
  };
  const j = async <T>(u: string): Promise<T | null> => { try { const r = await env.fetch(u, { signal: AbortSignal.timeout(1500) }); return r.ok ? ((await r.json()) as T) : null; } catch { return null; } };

  async function poll() {
    const entries = await j<{ idx: number; entry: { app: string; version: string; platform: string } }[]>(`${env.logUrl}/entries`);
    if (entries) { for (const l of entries.slice(seen.leaves)) emit("release", `${l.entry.app} ${l.entry.version} (${l.entry.platform}) appended to the log as leaf #${l.idx}`, "ok"); seen.leaves = entries.length; }
    const heads = await j<{ treeSize: number; cosigs: { witnessId: string }[] }[]>(`${env.logUrl}/sths`);
    for (const h of heads ?? []) {
      if (!seen.heads.has(h.treeSize)) { seen.heads.add(h.treeSize); emit("head", `log signed a head for ${h.treeSize} leaves`, "mute"); }
      if (h.cosigs.length >= env.verify.threshold && !seen.cosigned.has(h.treeSize)) { seen.cosigned.add(h.treeSize); emit("cosigned", `head ${h.treeSize} cosigned by ${h.cosigs.map((c) => c.witnessId).sort().join(", ")}`, "ok"); }
    }
    const sources = [...env.verify.witnesses.map((w) => w.url), env.monitor?.url].filter((u): u is string => !!u);
    for (const u of sources) for (const a of (await j<{ kind: string; app: string; version: string; raisedBy: string; raisedAt: string }[]>(`${u}/alerts`)) ?? []) {
      const k = `${a.kind}|${a.raisedBy}|${a.raisedAt}|${a.version}`;
      if (!seen.alerts.has(k)) { seen.alerts.add(k); stats.alerts++; emit("alert", `${a.raisedBy} raised ${a.kind}${a.app === "*" ? " (the whole log)" : ` for ${a.app} ${a.version}`}`, "bad", a); }
    }
  }
  let timer: ReturnType<typeof setInterval> | undefined, busy = false;
  return {
    emit, stats: () => ({ ...stats }), recent: () => [...buf],
    subscribe: (f: (e: Ev) => void) => { subs.add(f); return () => subs.delete(f); },
    client: (id: string, version: string, ok: boolean, reason?: string) => { ok ? stats.clientsVerified++ : stats.clientsBlocked++; emit("client", ok ? `client ${id} verified ${version}` : `client ${id} BLOCKED ${version}: ${reason}`, ok ? "ok" : "bad"); },
    attack: (text: string) => { stats.attacks++; emit("attack", text, "bad"); },
    /** After a reset: forget what was seen so alerts that return are reported again, and zero the counters. */
    reset: () => { seen.alerts.clear(); stats.clientsVerified = stats.clientsBlocked = stats.alerts = stats.attacks = 0; emit("attack", "demo reset: attacks removed, alerts cleared", "mute"); },
    start: () => { timer ??= setInterval(async () => { if (busy) return; busy = true; try { await poll(); } finally { busy = false; } }, 1000); },
    stop: () => timer && clearInterval(timer),
  };
}
