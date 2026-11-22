"use client";
import { useState } from "react";
import { Check, Swords, RotateCcw } from "lucide-react";
import { Badge, Card } from "./ui";
import { scenarios } from "@/lib/mock";

type Run = { id: number; expect: string; actual: string; ms: number };

export function AttackPanel() {
  const [runs, setRuns] = useState<Run[]>([]);
  const [busy, setBusy] = useState<number | null>(null);
  const [target, setTarget] = useState(7);

  const run = (id: number, expect: string) => {
    setBusy(id);
    // ponytail: simulated, actual === expect. Wire to demo/ attack scripts + client-sdk for real outcomes.
    setTimeout(() => { setRuns((r) => [{ id, expect, actual: expect, ms: 0 }, ...r]); setBusy(null); }, 900);
  };

  return (
    <>
      <div className="mb-8 flex flex-wrap items-center gap-4">
        <label className="flex items-center gap-3 text-lg text-mute">Target client
          <select value={target} onChange={(e) => setTarget(Number(e.target.value))} className="rounded-2xl border border-line bg-panel px-4 py-3 text-ink outline-none focus:border-bad">
            {Array.from({ length: 12 }, (_, i) => <option key={i} value={i + 1}>#{i + 1}</option>)}
          </select>
        </label>
        <button onClick={() => setRuns([])} className="ml-auto flex items-center gap-2 rounded-full border border-line px-6 py-3 text-lg text-mute transition hover:text-ink"><RotateCcw className="size-5" />Reset</button>
      </div>
      <div className="grid gap-5 [grid-template-columns:repeat(auto-fill,minmax(min(100%,26rem),1fr))]">
        {scenarios.map((s, i) => (
          <Card key={s.id} delay={i * 60} className="flex flex-col !p-6">
            <div className="flex items-center justify-between"><span className="text-5xl font-semibold text-mute">{s.id}</span><Badge tone="mute">{s.expect}</Badge></div>
            <p className="mt-4 flex-1 text-lg">{s.name}</p>
            <button disabled={busy !== null} onClick={() => run(s.id, s.expect)} className="mt-6 flex items-center justify-center gap-2 rounded-full bg-bad/90 py-3 text-lg font-semibold text-bg transition hover:scale-[1.03] active:scale-95 disabled:opacity-40">
              <Swords className={`size-5 ${busy === s.id ? "animate-spin" : ""}`} />{busy === s.id ? "Running…" : "Run attack"}
            </button>
          </Card>))}
      </div>
      <div className="mb-5 mt-14 flex items-center gap-4"><h2 className="text-3xl font-medium">Results</h2><Badge tone="mute">simulated</Badge></div>
      <div className="grid gap-3">
        {runs.length === 0 && <p className="text-lg text-mute">Nothing run yet.</p>}
        {runs.map((r, i) => (
          <div key={i} className="animate-rise flex flex-wrap items-center gap-x-6 gap-y-2 rounded-2xl border border-line bg-panel p-5 text-lg">
            <Badge tone="ok"><Check className="size-4" />pass</Badge><b>Scenario {r.id}</b>
            <span className="text-mute">expected</span><span className="font-mono">{r.expect}</span><span className="text-mute">actual</span><span className="font-mono">{r.actual}</span>
          </div>))}
      </div>
    </>
  );
}
