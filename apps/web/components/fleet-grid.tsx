"use client";
import { useEffect, useRef, useState } from "react";
import { Loader2, Play, RotateCcw, ShieldCheck, ShieldX, Download } from "lucide-react";
import { Card } from "./ui";

type S = "idle" | "checking" | "verified" | "installed" | "blocked";
const N = 12;

export function FleetGrid() {
  const [st, setSt] = useState<S[]>(Array(N).fill("idle"));
  const [target, setTarget] = useState<number | null>(null);
  const timers = useRef<number[]>([]);
  const set = (i: number, s: S) => setSt((x) => x.map((y, j) => (j === i ? s : y)));
  const later = (ms: number, f: () => void) => timers.current.push(window.setTimeout(f, ms));
  const clear = () => { timers.current.forEach(clearTimeout); timers.current = []; };
  useEffect(() => clear, []);

  const rollout = () => {
    clear(); setSt(Array(N).fill("idle"));
    // simulated until client-sdk + update-server are wired in
    for (let i = 0; i < N; i++) {
      later(i * 220, () => set(i, "checking"));
      later(i * 220 + 900, () => set(i, i === target ? "blocked" : "verified"));
      if (i !== target) later(i * 220 + 1700, () => set(i, "installed"));
    }
  };
  const reset = () => { clear(); setSt(Array(N).fill("idle")); };

  const style: Record<S, string> = {
    idle: "border-line text-mute", checking: "border-mute text-ink", verified: "border-ok text-ok shadow-[0_0_40px_-12px_var(--color-ok)]",
    installed: "border-ok bg-ok/10 text-ok", blocked: "border-bad bg-bad/10 text-bad shadow-[0_0_50px_-10px_var(--color-bad)]",
  };

  return (
    <>
      <div className="mb-8 flex flex-wrap items-center gap-4">
        <button onClick={rollout} className="flex items-center gap-2 rounded-full bg-ok px-7 py-3 text-lg font-semibold text-bg transition hover:scale-105 active:scale-95"><Play className="size-5" />Roll out 2.1.0</button>
        <button onClick={reset} className="flex items-center gap-2 rounded-full border border-line px-6 py-3 text-lg text-mute transition hover:text-ink"><RotateCcw className="size-5" />Reset</button>
        <label className="ml-auto flex items-center gap-3 text-lg text-mute">Attack 1 target
          <select value={target ?? ""} onChange={(e) => setTarget(e.target.value === "" ? null : Number(e.target.value))} className="rounded-2xl border border-line bg-panel px-4 py-3 text-ink outline-none focus:border-bad">
            <option value="">none</option>{Array.from({ length: N }, (_, i) => <option key={i} value={i}>client #{i + 1}</option>)}
          </select>
        </label>
      </div>
      <div className="grid gap-5 [grid-template-columns:repeat(auto-fill,minmax(15rem,1fr))]">
        {st.map((s, i) => {
          const I = { idle: Download, checking: Loader2, verified: ShieldCheck, installed: ShieldCheck, blocked: ShieldX }[s];
          return (
            <Card key={i} delay={i * 50} className={`!p-5 border-2 transition-all duration-500 ${style[s]} ${s === "blocked" ? "[animation:shake_.5s]" : ""}`}>
              <div className="flex items-center justify-between"><span className="font-mono text-lg">#{i + 1}</span><I className={`size-6 ${s === "checking" ? "animate-spin" : ""}`} /></div>
              <div className="mt-5 text-sm text-mute">notepad-minus 2.0.2 → 2.1.0</div>
              <div className="mt-1 text-xl font-medium capitalize">{s}</div>
              {s === "blocked" && <div className="mt-2 text-sm">HASH_MISMATCH: file differs from the logged hash</div>}
            </Card>);
        })}
      </div>
    </>
  );
}
