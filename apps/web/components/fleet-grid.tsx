"use client";
import { useRef, useState } from "react";
import { Loader2, Play, RotateCcw, ShieldCheck, ShieldX, Download, Check, X, Minus, Swords } from "lucide-react";
import { Badge, Card } from "./ui";

type CheckRow = { id: string; label: string; status: "pass" | "fail" | "skip"; detail?: string };
type Result = { id: string; version: string; state: "verified" | "blocked"; reason?: string; detail?: string; checks: CheckRow[]; ms: number; bytes: number };
type S = "idle" | "checking" | "verified" | "installed" | "blocked";
const N = 12, ids = Array.from({ length: N }, (_, i) => `c${i + 1}`);

export function FleetGrid() {
  const [st, setSt] = useState<Record<string, S>>(() => Object.fromEntries(ids.map((i) => [i, "idle" as S])));
  const [res, setRes] = useState<Record<string, Result>>({});
  const [target, setTarget] = useState("c7");
  const [armed, setArmed] = useState<string[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const src = useRef<EventSource | null>(null);

  const call = async (path: string, body?: unknown) => {
    const r = await fetch(`/api/demo/${path}`, { method: "POST", body: JSON.stringify(body ?? {}) });
    if (!r.ok) throw new Error(((await r.json().catch(() => null)) as { error?: string } | null)?.error ?? `HTTP ${r.status}`);
  };
  const clear = () => { src.current?.close(); setSt(Object.fromEntries(ids.map((i) => [i, "idle" as S]))); setRes({}); setOpen(null); setBusy(false); };

  const arm = async (key: string, path: string, body?: unknown) => {
    setErr(null);
    try { await call(path, body); setArmed((a) => [...new Set([...a, key])]); } catch (e) { setErr(e instanceof Error ? e.message : String(e)); }
  };
  const resetAll = async () => { clear(); setErr(null); try { await call("reset"); setArmed([]); } catch (e) { setErr(e instanceof Error ? e.message : String(e)); } };

  const rollout = async () => {
    clear(); setErr(null); setBusy(true);
    setSt(Object.fromEntries(ids.map((i) => [i, "checking" as S])));
    const es = new EventSource(`/api/demo/fleet/stream?n=${N}`); src.current = es;
    es.addEventListener("result", (ev) => {
      const r: Result = JSON.parse((ev as MessageEvent).data);
      setRes((x) => ({ ...x, [r.id]: r }));
      setSt((x) => ({ ...x, [r.id]: r.state }));
      if (r.state === "verified") setTimeout(() => setSt((x) => ({ ...x, [r.id]: "installed" })), 700);
    });
    es.addEventListener("done", () => { es.close(); setBusy(false); });
    es.onerror = () => { es.close(); setBusy(false); setErr("lost the demo server stream: is the stack running (log, witnesses, update-server, demo server)?"); setSt(Object.fromEntries(ids.map((i) => [i, "idle" as S]))); };
  };

  const style: Record<S, string> = {
    idle: "border-line text-mute", checking: "border-mute text-ink", verified: "border-ok text-ok shadow-[0_0_40px_-12px_var(--color-ok)]",
    installed: "border-ok bg-ok/10 text-ok", blocked: "border-bad bg-bad/10 text-bad shadow-[0_0_50px_-10px_var(--color-bad)]",
  };
  const done = Object.values(res), ms = done.map((r) => r.ms).sort((a, b) => a - b);
  const CI = { pass: Check, fail: X, skip: Minus } as const;

  return (
    <>
      <div className="mb-5 flex flex-wrap items-center gap-4">
        <button onClick={rollout} disabled={busy} className="flex items-center gap-2 rounded-full bg-accent px-7 py-3 text-lg font-semibold text-bg transition hover:scale-105 active:scale-95 disabled:opacity-40"><Play className="size-5" />Roll out</button>
        <button onClick={resetAll} className="flex items-center gap-2 rounded-full border border-line px-6 py-3 text-lg text-mute transition hover:text-ink"><RotateCcw className="size-5" />Reset everything</button>
      </div>
      <div className="mb-8 flex flex-wrap items-center gap-3 rounded-3xl border border-line bg-panel/60 p-4">
        <span className="flex items-center gap-2 px-2 text-mute"><Swords className="size-5" />Attacks, then roll out</span>
        <label className="flex items-center gap-2 text-mute">target
          <select value={target} onChange={(e) => setTarget(e.target.value)} className="rounded-xl border border-line bg-panel px-3 py-2 text-ink outline-none focus:border-bad">
            {ids.map((i, k) => <option key={i} value={i}>client #{k + 1}</option>)}
          </select>
        </label>
        {([
          ["1", "1 · swap one client's binary", "attack1", { clientId: target }],
          ["5", "5 · fork the log for the target", "attacks/fork", { clientId: target }],
          ["4", "4 · stolen-key release", "attacks/stolen-key", {}],
          ["9", "9 · tamper a leaf in Postgres", "attacks/tamper", {}],
        ] as const).map(([k, label, path, body]) => (
          <button key={k} onClick={() => arm(k, path, body)} className={`rounded-full border px-4 py-2 transition ${armed.includes(k) ? "border-bad bg-bad/15 text-bad" : "border-line text-ink hover:border-bad hover:text-bad"}`}>{label}{armed.includes(k) ? " · armed" : ""}</button>
        ))}
      </div>
      {err && <p className="mb-6 rounded-2xl border border-bad/50 bg-bad/10 p-5 text-lg text-bad">{err}</p>}
      {done.length > 0 && <div className="mb-6 flex flex-wrap gap-3">
        <Badge tone="ok">{done.filter((r) => r.state === "verified").length} verified</Badge>
        <Badge tone={done.some((r) => r.state === "blocked") ? "bad" : "mute"}>{done.filter((r) => r.state === "blocked").length} blocked</Badge>
        <Badge tone="mute">median {ms[Math.floor(ms.length / 2)].toFixed(0)} ms</Badge>
        <Badge tone="mute">{done[0].bytes} B of proofs + head per update</Badge>
      </div>}
      <div className="grid gap-5 [grid-template-columns:repeat(auto-fill,minmax(15rem,1fr))]">
        {ids.map((id, i) => {
          const s = st[id], r = res[id], I = { idle: Download, checking: Loader2, verified: ShieldCheck, installed: ShieldCheck, blocked: ShieldX }[s];
          return (
            <Card key={id} delay={i * 50} className={`!p-5 border-2 transition-all duration-500 ${style[s]} ${s === "blocked" ? "[animation:shake_.5s]" : ""}`}>
              <button onClick={() => r && setOpen(open === id ? null : id)} className="block w-full text-left">
                <div className="flex items-center justify-between"><span className="font-mono text-lg">#{i + 1}</span><I className={`size-6 ${s === "checking" ? "animate-spin" : ""}`} /></div>
                <div className="mt-5 text-sm text-mute">notepad-minus 2.0.0 → {r?.version ?? "…"}</div>
                <div className="mt-1 text-xl font-medium capitalize">{s}</div>
                {r && <div className="mt-1 text-sm text-mute">{r.ms.toFixed(0)} ms</div>}
                {s === "blocked" && <div className="mt-2 break-all text-sm"><b>{r?.reason}</b><span className="line-clamp-2 text-xs opacity-80">{r?.detail}</span></div>}
              </button>
              {open === id && r && <ul className="mt-4 grid gap-1 border-t border-line pt-3 text-sm">
                {r.checks.map((c) => { const CIcon = CI[c.status]; return <li key={c.id} className={`flex items-start gap-2 ${c.status === "fail" ? "text-bad" : c.status === "pass" ? "text-ok" : "text-mute"}`}><CIcon className="mt-0.5 size-4 shrink-0" />{c.label}</li>; })}
              </ul>}
            </Card>);
        })}
      </div>
    </>
  );
}
