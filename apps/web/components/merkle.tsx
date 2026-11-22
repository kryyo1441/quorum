"use client";
import { useState } from "react";
import { Card, Badge } from "./ui";
import { leafHashes, releases, short } from "@/lib/mock";

const N = leafHashes.length; // 8 leaves => 4 levels. Hashes are mock until log-core lands.
const W = 1000, H = 420, levels = Math.log2(N) + 1;
const pos = (lvl: number, i: number) => ({ x: ((i + 0.5) * W) / (N >> lvl), y: H - 40 - (lvl * (H - 80)) / (levels - 1) });

export function Merkle() {
  const [sel, setSel] = useState(4);
  // inclusion path: the node at each level on the way up, plus its sibling (the proof hashes).
  const path = Array.from({ length: levels }, (_, l) => sel >> l);
  const on = (l: number, i: number) => path[l] === i;
  const sib = (l: number, i: number) => l < levels - 1 && path[l] === (i ^ 1);

  return (
    <div className="grid gap-6 [grid-template-columns:repeat(auto-fit,minmax(min(100%,28rem),1fr))]">
      <Card className="!p-4 sm:col-span-full xl:col-span-2" delay={100}>
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="Merkle tree">
          {Array.from({ length: levels - 1 }, (_, l) => Array.from({ length: N >> l }, (_, i) => {
            const a = pos(l, i), b = pos(l + 1, i >> 1), hot = on(l, i);
            return <path key={`${l}-${i}`} d={`M${a.x} ${a.y} L${b.x} ${b.y}`} pathLength={1} strokeDasharray={hot ? "6 6" : 1}
              className={`transition-colors duration-500 ${hot ? "stroke-ok [animation:flow_1s_linear_infinite]" : "stroke-line"}`} fill="none" strokeWidth={hot ? 3 : 2} />;
          }))}
          {Array.from({ length: levels }, (_, l) => Array.from({ length: N >> l }, (_, i) => {
            const { x, y } = pos(l, i), hot = on(l, i), s = sib(l, i);
            return (
              <g key={`${l}-${i}`} onClick={() => l === 0 && setSel(i)} className={l === 0 ? "cursor-pointer" : ""}
                style={{ transformOrigin: `${x}px ${y}px`, animation: `pop .5s ${l * 150 + i * 40}ms cubic-bezier(.2,.9,.3,1.4) both` }}>
                <circle cx={x} cy={y} r={hot ? 22 : 16} className={`transition-all duration-500 ${hot ? "fill-ok stroke-ok" : s ? "fill-bg stroke-ok" : "fill-panel stroke-line hover:stroke-mute"}`} strokeWidth={2} />
                {l === 0 && <text x={x} y={y + 5} textAnchor="middle" className={`pointer-events-none text-[14px] font-mono ${hot ? "fill-bg" : "fill-mute"}`}>{i}</text>}
              </g>);
          }))}
        </svg>
      </Card>

      <Card delay={250}>
        <div className="mb-5 flex flex-wrap items-center justify-between gap-3"><h2 className="text-2xl font-medium">Inclusion proof</h2><Badge tone="mute">mock hashes</Badge></div>
        <p className="text-mute">Leaf #{sel}: <span className="font-mono text-ink">{releases[sel].app} {releases[sel].version}</span></p>
        <ol className="mt-5 space-y-3 font-mono text-sm">
          <li className="flex gap-3"><span className="text-ok">leaf</span><span className="break-all">{short(leafHashes[sel], 16)}</span></li>
          {path.slice(0, -1).map((_, l) => (
            <li key={l} className="animate-rise flex gap-3" style={{ animationDelay: `${l * 120}ms` }}>
              <span className="text-mute">sib L{l}</span><span className="break-all">{short(leafHashes[((path[l] ^ 1) << l) % N], 16)}</span>
            </li>))}
          <li className="flex gap-3"><span className="text-ok">root</span><span className="break-all">cosigned head</span></li>
        </ol>
        <p className="mt-5 text-sm text-mute">Click any leaf. In-browser verification arrives with <code>log-core</code>.</p>
      </Card>
    </div>
  );
}
