"use client";
import { useState } from "react";
import { Radio, ShieldAlert, X } from "lucide-react";
import { Badge, Card } from "./ui";
import { alerts, short, sths, witnesses } from "@/lib/mock";

// triangle layout for gossip lines
const P = [{ x: 150, y: 40 }, { x: 40, y: 200 }, { x: 260, y: 200 }];
const edges = [[0, 1], [1, 2], [0, 2]];

export function WitnessesView() {
  const [open, setOpen] = useState<(typeof alerts)[number] | null>(null);
  const head = sths.at(-1)!;
  return (
    <>
      <div className="grid gap-6 [grid-template-columns:repeat(auto-fit,minmax(min(100%,22rem),1fr))]">
        {witnesses.map((w, i) => (
          <Card key={w} delay={i * 120}>
            <div className="flex items-center justify-between"><h2 className="text-3xl font-semibold">{w}</h2><Badge tone="ok"><Radio className="size-4 animate-pulse" />online</Badge></div>
            <p className="mt-6 text-sm uppercase tracking-wider text-mute">Last cosigned head</p>
            <p className="mt-1 font-mono text-lg">{short(head.rootHash, 12)}</p>
            <p className="mt-1 text-mute">tree size {head.treeSize}</p>
          </Card>
        ))}
        <Card delay={400} className="flex items-center justify-center">
          <svg viewBox="0 0 300 240" className="w-full max-w-sm" role="img" aria-label="Witness gossip">
            {edges.map(([a, b]) => <line key={`${a}${b}`} x1={P[a].x} y1={P[a].y} x2={P[b].x} y2={P[b].y} strokeWidth={2} strokeDasharray="6 6" className="stroke-ok [animation:flow_1.2s_linear_infinite]" />)}
            {P.map((p, i) => <g key={i}><circle cx={p.x} cy={p.y} r={22} className="fill-panel stroke-ok" strokeWidth={2} /><text x={p.x} y={p.y + 5} textAnchor="middle" className="fill-ink font-mono text-[14px]">{witnesses[i]}</text></g>)}
          </svg>
        </Card>
      </div>

      <h2 className="mb-5 mt-14 text-3xl font-medium">Alerts</h2>
      <div className="grid gap-4">
        {alerts.map((a) => (
          <button key={a.id} onClick={() => setOpen(a)} className="animate-rise flex flex-wrap items-center gap-x-6 gap-y-2 rounded-3xl border border-bad/40 bg-bad/10 p-6 text-left text-lg transition hover:scale-[1.01]">
            <ShieldAlert className="size-7 text-bad" /><b className="text-bad">{a.kind}</b>
            <span className="font-mono">{a.app} {a.version}</span><span className="text-mute">{a.platform} · raised by {a.raisedBy}</span>
          </button>))}
      </div>

      {open && <div className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm" onClick={() => setOpen(null)} />}
      <aside className={`fixed inset-y-0 right-0 z-40 w-[min(100vw,36rem)] overflow-y-auto border-l border-line bg-panel p-8 transition-transform duration-500 ${open ? "translate-x-0" : "translate-x-full"}`}>
        {open && <>
          <button onClick={() => setOpen(null)} aria-label="close" className="mb-6 rounded-full p-2 hover:bg-line"><X className="size-6" /></button>
          <h3 className="text-3xl font-semibold text-bad">{open.kind}</h3>
          <p className="mt-2 text-mute">{open.app} {open.version} · {open.platform}</p>
          <p className="mt-8 text-sm uppercase tracking-wider text-mute">Evidence (mock)</p>
          <pre className="mt-2 overflow-x-auto rounded-2xl bg-bg p-5 font-mono text-sm">{JSON.stringify(open.evidence, null, 2)}</pre>
        </>}
      </aside>
    </>
  );
}
