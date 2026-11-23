"use client";
import { useState } from "react";
import { Check, FileUp, Loader2, Minus, X } from "lucide-react";
import { checkUpdate, type Check as Row, type VerifyConfig } from "@uw/client-sdk";
import type { ReleaseEntry } from "@uw/shared";
import { Card } from "./ui";

const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");

export function Verifier({ cfg }: { cfg: VerifyConfig | { error: string } }) {
  const [hash, setHash] = useState("");
  const [rows, setRows] = useState<Row[] | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const S = { pass: [Check, "text-ok border-ok/50 bg-ok/10"], fail: [X, "text-bad border-bad/50 bg-bad/10"], skip: [Minus, "text-mute border-line"] } as const;
  if ("error" in cfg) return <p className="rounded-2xl border border-bad/50 bg-bad/10 p-5 text-lg text-bad">{cfg.error}</p>;

  /** `bytes` is set when a file was dropped (so the hash check is real); with only a pasted hash that row is reported as skipped. */
  const go = async (h: string, bytes?: Uint8Array) => {
    const t = h.trim().toLowerCase(); setHash(t); setRows(null); setNote(null);
    if (!t) return;
    setBusy(true);
    try {
      const l = await fetch(`${cfg.logUrl}/entries`, { signal: AbortSignal.timeout(5000) });
      if (!l.ok) throw new Error(`log returned ${l.status}`);
      const found = ((await l.json()) as { entry: ReleaseEntry }[]).find((x) => x.entry.sha256 === t)?.entry;
      if (!found) { setRows([{ id: "inclusion", label: "The log holds a release with this hash", status: "fail", reason: "NOT_IN_LOG", detail: "no such release in the log: do not install" }]); return; }
      const { checks } = await checkUpdate(bytes ?? new Uint8Array(), { ...found, sha256: found.sha256 }, { ...cfg, expected: { app: found.app, platform: found.platform } });
      if (!bytes) { checks[0] = { ...checks[0], status: "skip", reason: undefined, detail: "only a hash was pasted: drop the file to check it too" }; }
      setRows(checks);
    } catch (e) { setNote(`could not reach the log: ${e instanceof Error ? e.message : e}. Failing closed: do not install.`); }
    finally { setBusy(false); }
  };
  const file = async (f: File) => { const b = await f.arrayBuffer(); await go(hex(await crypto.subtle.digest("SHA-256", b)), new Uint8Array(b)); };

  return (
    <div className="grid gap-6 [grid-template-columns:repeat(auto-fit,minmax(min(100%,30rem),1fr))]">
      <Card delay={80}>
        <label className="text-sm uppercase tracking-wider text-mute">SHA-256</label>
        <input value={hash} onChange={(e) => void go(e.target.value)} placeholder="paste a hash" spellCheck={false}
          className="mt-3 w-full rounded-2xl border border-line bg-bg px-5 py-4 font-mono text-lg outline-none transition focus:border-ok" />
        <label onDragOver={(e) => e.preventDefault()} onDrop={(e) => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) void file(f); }}
          className="mt-6 flex cursor-pointer flex-col items-center gap-3 rounded-3xl border-2 border-dashed border-line p-10 text-center text-lg text-mute transition hover:border-ok hover:text-ok">
          <FileUp className="size-10" />Drop a file to verify it
          <input type="file" hidden onChange={(e) => { const f = e.target.files?.[0]; if (f) void file(f); }} />
        </label>
      </Card>
      <Card delay={200}>
        <h2 className="mb-5 flex items-center gap-3 text-2xl font-medium">Checks{busy && <Loader2 className="size-5 animate-spin" />}</h2>
        {!rows && !note && <p className="text-lg text-mute">Waiting for a hash.</p>}
        {note && <p className="text-lg text-bad">{note}</p>}
        <ol className="grid gap-3">
          {rows?.map((r, i) => { const [I, c] = S[r.status]; return (
            <li key={hash + i} style={{ animationDelay: `${i * 110}ms` }} className={`animate-rise rounded-2xl border px-5 py-4 text-lg ${c}`}>
              <div className="flex items-center gap-4"><I className="size-5 shrink-0" />{r.label}</div>
              {r.detail && <p className="mt-1 pl-9 text-sm opacity-80">{r.reason ? `${r.reason}: ` : ""}{r.detail}</p>}
            </li>); })}
        </ol>
      </Card>
    </div>
  );
}
