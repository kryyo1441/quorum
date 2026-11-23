"use client";
import { useEffect, useState } from "react";
import { Check, Swords, X, Play } from "lucide-react";
import { Badge, Card } from "./ui";

type Sc = { n: number; name: string; attack: string; expected: string };
type Run = { naive?: string; n: number; actual: string; pass: boolean; evidence: string[]; ms: number; alertMs?: number; expected: string };
type Metrics = { note: string; verifyMs: { p50: number; p95: number }; hashMs: number; overheadBytes: number; appendsPerSecond: number; publishToCosignedMs: number };

export function AttackPanel() {
  const [list, setList] = useState<Sc[]>([]);
  const [runs, setRuns] = useState<Record<number, Run>>({});
  const [busy, setBusy] = useState<number | "all" | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [m, setM] = useState<Metrics | null>(null);

  useEffect(() => { fetch("/api/demo/scenarios").then((r) => (r.ok ? r.json() : Promise.reject(new Error(`demo server: HTTP ${r.status}`)))).then(setList).catch((e) => setErr(String(e.message ?? e))); }, []);

  const run = async (n: number) => {
    const r = await fetch(`/api/demo/scenarios/${n}/run`, { method: "POST" });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const x: Run = await r.json();
    setRuns((p) => ({ ...p, [n]: x }));
  };
  const go = async (n: number | "all") => {
    setBusy(n); setErr(null);
    try { if (n === "all") for (const s of list) await run(s.n); else await run(n); } catch (e) { setErr(e instanceof Error ? e.message : String(e)); }
    setBusy(null);
  };
  const metrics = async () => { setBusy("all"); try { const r = await fetch("/api/demo/metrics"); setM(r.ok ? await r.json() : null); } finally { setBusy(null); } };
  const results = list.filter((s) => runs[s.n]), passed = results.filter((s) => runs[s.n].pass).length;

  return (
    <>
      <div className="mb-8 flex flex-wrap items-center gap-4">
        <button disabled={busy !== null || !list.length} onClick={() => go("all")} className="flex items-center gap-2 rounded-full bg-accent px-7 py-3 text-lg font-semibold text-bg transition hover:scale-105 active:scale-95 disabled:opacity-40"><Play className="size-5" />Run all 10</button>
        <button disabled={busy !== null || !list.length} onClick={metrics} className="rounded-full border border-line px-6 py-3 text-lg text-mute transition hover:text-ink disabled:opacity-40">Measure latency and overhead</button>
        {results.length > 0 && <Badge tone={passed === results.length ? "ok" : "bad"}>{passed} / {results.length} as expected</Badge>}
      </div>
      {err && <p className="mb-6 rounded-2xl border border-bad/50 bg-bad/10 p-5 text-lg text-bad">{err}</p>}
      {m && <Card className="mb-8"><div className="flex flex-wrap gap-x-10 gap-y-3 text-lg">
        <span><b>{m.verifyMs.p50.toFixed(0)} ms</b> <span className="text-mute">median verify</span></span><span><b>{m.verifyMs.p95.toFixed(0)} ms</b> <span className="text-mute">p95</span></span>
        <span><b>{m.hashMs.toFixed(2)} ms</b> <span className="text-mute">hashing</span></span><span><b>{m.overheadBytes} B</b> <span className="text-mute">proofs + head per update</span></span>
        <span><b>{m.appendsPerSecond.toFixed(0)}</b> <span className="text-mute">log appends / s</span></span><span className="w-full text-sm text-mute">{m.note}</span></div></Card>}
      <div className="grid gap-5 [grid-template-columns:repeat(auto-fill,minmax(min(100%,26rem),1fr))]">
        {list.map((s, i) => {
          const r = runs[s.n];
          return (
            <Card key={s.n} delay={i * 60} className="flex flex-col !p-6">
              <div className="flex items-center justify-between"><span className="text-5xl font-semibold text-mute">{s.n}</span><Badge tone="mute">{s.expected}</Badge></div>
              <p className="mt-4 text-xl font-medium">{s.name}</p><p className="mt-1 flex-1 text-mute">{s.attack}</p>
              <button disabled={busy !== null} onClick={() => go(s.n)} className="mt-6 flex items-center justify-center gap-2 rounded-full bg-bad/90 py-3 text-lg font-semibold text-bg transition hover:scale-[1.03] active:scale-95 disabled:opacity-40">
                <Swords className={`size-5 ${busy === s.n || busy === "all" ? "animate-spin" : ""}`} />{busy === s.n ? "Running…" : "Run attack"}
              </button>
              {r && <div className="animate-rise mt-5 grid gap-2 border-t border-line pt-4">
                <div className="flex flex-wrap items-center gap-3"><Badge tone={r.pass ? "ok" : "bad"}>{r.pass ? <Check className="size-4" /> : <X className="size-4" />}{r.pass ? "as expected" : "UNEXPECTED"}</Badge>
                  <span className="text-sm text-mute">{r.ms.toFixed(0)} ms{r.alertMs !== undefined && ` · attack to alert ${r.alertMs.toFixed(0)} ms`}</span></div>
                <p className="font-mono text-sm">{r.actual}</p>
                {r.naive && <p className={`rounded-xl border px-3 py-2 text-sm ${r.naive.includes("INSTALLS") ? "border-bad/50 bg-bad/10 text-bad" : "border-line text-mute"}`}><b>Signature-only updater:</b> {r.naive}</p>}
                <ul className="grid gap-1 text-sm text-mute">{r.evidence.map((e, k) => <li key={k}>· {e}</li>)}</ul>
              </div>}
            </Card>);
        })}
      </div>
      {!list.length && !err && <p className="text-lg text-mute">Loading scenarios…</p>}
    </>
  );
}
