"use client";
import { useState } from "react";
import { Check, FileUp, Minus, X } from "lucide-react";
import { Card } from "./ui";
import { releases, sths } from "@/lib/mock";

type Row = { label: string; state: "pass" | "fail" | "skip" };

// ponytail: checks run against mock data; swap for client-sdk verifyUpdate when it lands.
function check(hash: string): Row[] {
  const r = releases.find((x) => x.sha256 === hash);
  const k = sths.at(-1)!.cosigs.length;
  if (!r) return [
    { label: "File hash is well-formed", state: /^[0-9a-f]{64}$/.test(hash) ? "pass" : "fail" },
    { label: "Vendor signature valid", state: "skip" }, { label: "Inclusion proof in log (NOT_IN_LOG)", state: "fail" },
    { label: "STH signed by log with ≥2 witness cosigs", state: "skip" }, { label: "STH is fresh", state: "skip" }, { label: "No open split-view alert", state: "skip" },
  ];
  return [
    { label: "File hash matches the manifest", state: "pass" }, { label: "Vendor signature valid", state: "pass" },
    { label: "Inclusion proof verifies against STH root", state: "pass" },
    { label: `STH signed by log with ≥2 witness cosigs (${k}/3)`, state: k >= 2 ? "pass" : "fail" },
    { label: "STH is fresh", state: "pass" }, { label: "No open split-view alert", state: "pass" },
  ];
}
const hashFile = async (f: File) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", await f.arrayBuffer()))].map((b) => b.toString(16).padStart(2, "0")).join("");

export function Verifier() {
  const [hash, setHash] = useState("");
  const [rows, setRows] = useState<Row[] | null>(null);
  const go = (h: string) => { const t = h.trim().toLowerCase(); setHash(t); setRows(t ? check(t) : null); };
  const S = { pass: [Check, "text-ok border-ok/50 bg-ok/10"], fail: [X, "text-bad border-bad/50 bg-bad/10"], skip: [Minus, "text-mute border-line"] } as const;

  return (
    <div className="grid gap-6 [grid-template-columns:repeat(auto-fit,minmax(min(100%,30rem),1fr))]">
      <Card delay={80}>
        <label className="text-sm uppercase tracking-wider text-mute">SHA-256</label>
        <input value={hash} onChange={(e) => go(e.target.value)} placeholder="paste a hash" spellCheck={false}
          className="mt-3 w-full rounded-2xl border border-line bg-bg px-5 py-4 font-mono text-lg outline-none transition focus:border-ok" />
        <button onClick={() => go(releases[5].sha256)} className="mt-3 text-sm text-mute underline-offset-4 hover:text-ok hover:underline">try a logged hash</button>
        <label onDragOver={(e) => e.preventDefault()} onDrop={async (e) => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) go(await hashFile(f)); }}
          className="mt-6 flex cursor-pointer flex-col items-center gap-3 rounded-3xl border-2 border-dashed border-line p-10 text-center text-lg text-mute transition hover:border-ok hover:text-ok">
          <FileUp className="size-10" />Drop a file to hash it here
          <input type="file" hidden onChange={async (e) => { const f = e.target.files?.[0]; if (f) go(await hashFile(f)); }} />
        </label>
      </Card>
      <Card delay={200}>
        <h2 className="mb-5 text-2xl font-medium">Checks</h2>
        {!rows && <p className="text-lg text-mute">Waiting for a hash.</p>}
        <ol className="grid gap-3">
          {rows?.map((r, i) => { const [I, c] = S[r.state]; return (
            <li key={hash + i} style={{ animationDelay: `${i * 110}ms` }} className={`animate-rise flex items-center gap-4 rounded-2xl border px-5 py-4 text-lg ${c}`}>
              <I className="size-5 shrink-0" />{r.label}
            </li>); })}
        </ol>
      </Card>
    </div>
  );
}
