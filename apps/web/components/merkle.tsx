"use client";
import { useMemo, useState, useTransition } from "react";
import { Check, X } from "lucide-react";
import { hashChildren, leafHashOfEntry, verifyInclusion, verifyLogSig } from "@uw/log-core";
import type { ReleaseEntry, STH } from "@uw/shared";
import { Badge, Card } from "./ui";
import { fetchProof } from "@/app/log/actions";
import { short } from "@/lib/mock";

type Leaf = { idx: number; entry: ReleaseEntry; leafHash: string };
type Node = { lo: number; hi: number; height: number; hash: string; left?: Node; right?: Node; x: number };
type Row = { label: string; ok: boolean };

const W = 1000, MAX_DRAW = 32;
const split = (n: number) => 2 ** Math.floor(Math.log2(n - 1));

function build(hashes: string[], lo: number, hi: number): Node {
  if (hi - lo === 1) return { lo, hi, height: 0, hash: hashes[lo], x: (lo + 0.5) * (W / hashes.length) };
  const k = split(hi - lo), left = build(hashes, lo, lo + k), right = build(hashes, lo + k, hi);
  return { lo, hi, height: Math.max(left.height, right.height) + 1, hash: hashChildren(left.hash, right.hash), left, right, x: (left.x + right.x) / 2 };
}

/** The tree is rebuilt in the browser from the leaf hashes; the proof check below trusts only the signed head, not the server's tree. */
export function Merkle({ leaves, head, logKey }: { leaves: Leaf[]; head: STH; logKey: string }) {
  const hashes = useMemo(() => leaves.slice(0, head.treeSize).map((l) => l.leafHash), [leaves, head.treeSize]);
  const tree = useMemo(() => build(hashes, 0, hashes.length), [hashes]);
  const [sel, setSel] = useState<number | null>(null);
  const [rows, setRows] = useState<Row[] | null>(null);
  const [pending, start] = useTransition();
  const H = 120 + tree.height * 70, y = (n: Node) => H - 40 - (n.height * (H - 80)) / Math.max(tree.height, 1);
  const rootMatches = tree.hash === head.rootHash;

  const pick = (i: number) => {
    setSel(i); setRows(null);
    start(async () => {
      const path = await fetchProof(i, head.treeSize);
      const l = leaves[i];
      setRows([
        { label: "Leaf hash recomputed from the entry matches the log's", ok: leafHashOfEntry(l.entry) === l.leafHash },
        { label: "Head signature valid under the log key", ok: verifyLogSig(head, logKey) },
        { label: `Inclusion proof reaches the head's root (size ${head.treeSize})`, ok: !!path && verifyInclusion(l.leafHash, i, head.treeSize, path, head.rootHash) },
      ]);
    });
  };

  const nodes: Node[] = []; (function walk(n: Node) { nodes.push(n); if (n.left) { walk(n.left); walk(n.right!); } })(tree);
  const onPath = (n: Node) => sel !== null && n.lo <= sel && sel < n.hi;
  const isSibling = (n: Node, parent?: Node) => !!parent && onPath(parent) && !onPath(n);
  const parentOf = new Map<Node, Node>(); nodes.forEach((n) => { if (n.left) { parentOf.set(n.left, n); parentOf.set(n.right!, n); } });

  return (
    <div className="grid gap-6 [grid-template-columns:repeat(auto-fit,minmax(min(100%,28rem),1fr))]">
      <Card className="!p-4 sm:col-span-full xl:col-span-2" delay={100}>
        {hashes.length > MAX_DRAW ? <p className="p-6 text-lg text-mute">{hashes.length} leaves is too many to draw. Pick an index below.</p> : (
          <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="Merkle tree">
            {nodes.filter((n) => n.left).flatMap((n) => [n.left!, n.right!].map((c) => {
              const hot = onPath(c);
              return <path key={`${c.lo}-${c.hi}`} d={`M${c.x} ${y(c)} L${n.x} ${y(n)}`} fill="none" strokeWidth={hot ? 3 : 2} strokeDasharray={hot ? "6 6" : undefined}
                className={`transition-colors duration-500 ${hot ? "stroke-ok [animation:flow_1s_linear_infinite]" : "stroke-line"}`} />;
            }))}
            {nodes.map((n, k) => {
              const hot = onPath(n), sib = isSibling(n, parentOf.get(n)), leaf = !n.left;
              return (
                <g key={`${n.lo}-${n.hi}`} onClick={() => leaf && pick(n.lo)} className={leaf ? "cursor-pointer" : ""}
                  style={{ transformOrigin: `${n.x}px ${y(n)}px`, animation: `pop .5s ${n.height * 150 + k * 12}ms cubic-bezier(.2,.9,.3,1.4) both` }}>
                  <circle cx={n.x} cy={y(n)} r={hot ? 22 : 16} strokeWidth={2}
                    className={`transition-all duration-500 ${hot ? "fill-ok stroke-ok" : sib ? "fill-bg stroke-ok" : "fill-panel stroke-line hover:stroke-mute"}`} />
                  {leaf && <text x={n.x} y={y(n) + 5} textAnchor="middle" className={`pointer-events-none font-mono text-[14px] ${hot ? "fill-bg" : "fill-mute"}`}>{n.lo}</text>}
                </g>);
            })}
          </svg>)}
        <div className="flex flex-wrap items-center gap-3 px-4 pb-2 text-sm text-mute">
          <Badge tone={rootMatches ? "ok" : "bad"}>{rootMatches ? "root recomputed in browser matches head" : "recomputed root DIFFERS from head"}</Badge>
          <span className="font-mono">{short(head.rootHash, 12)}</span>
        </div>
      </Card>

      <Card delay={250}>
        <h2 className="mb-5 text-2xl font-medium">Verify in browser</h2>
        {sel === null ? <p className="text-lg text-mute">Click a leaf to fetch its proof from the log and check it here.</p> : (
          <>
            <p className="text-mute">Leaf #{sel}: <span className="font-mono text-ink">{leaves[sel].entry.app} {leaves[sel].entry.version}</span> <span className="text-sm">({leaves[sel].entry.platform})</span></p>
            <ol className="mt-5 grid gap-3">
              {pending && <li className="text-mute">Fetching proof…</li>}
              {rows?.map((r, i) => (
                <li key={`${sel}-${i}`} style={{ animationDelay: `${i * 120}ms` }} className={`animate-rise flex items-start gap-3 rounded-2xl border px-4 py-3 ${r.ok ? "border-ok/50 bg-ok/10 text-ok" : "border-bad/50 bg-bad/10 text-bad"}`}>
                  {r.ok ? <Check className="mt-1 size-5 shrink-0" /> : <X className="mt-1 size-5 shrink-0" />}{r.label}
                </li>))}
            </ol>
          </>)}
        <p className="mt-5 text-sm text-mute">The log key is fetched from the same server here. A real client pins it.</p>
      </Card>
    </div>
  );
}
