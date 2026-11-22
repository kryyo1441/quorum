"use client";
import { useRef, useState } from "react";
import { Laptop, Monitor, Plus, ShieldAlert, ShieldCheck, Terminal } from "lucide-react";
import { Badge, Card } from "./ui";
import { platforms, releases as seed, short, type Platform, type Release } from "@/lib/mock";

const Icon = { "win-x64": Monitor, "mac-arm64": Laptop, "linux-x64": Terminal } as const;

export function ReleasesTable() {
  const [rows, setRows] = useState<Release[]>(seed);
  const dlg = useRef<HTMLDialogElement>(null);
  const unapproved = rows.filter((r) => !r.approved);

  const publish = (f: FormData) => {
    const sha256 = [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, "0")).join("");
    // ponytail: local-only until log-server exists; then POST /entries via the vendor CLI path.
    setRows((r) => [...r, { idx: r.length, app: String(f.get("app")), version: String(f.get("version")), platform: f.get("platform") as Platform, sha256, publishedAt: new Date().toISOString(), approved: true }]);
    dlg.current?.close();
  };

  return (
    <>
      {unapproved.length > 0 && (
        <div className="animate-rise mb-6 flex flex-wrap items-center gap-4 rounded-3xl border border-bad/50 bg-bad/10 p-6 text-lg text-bad">
          <ShieldAlert className="size-7 animate-pulse" />
          <b>UNAPPROVED_RELEASE</b> {unapproved.map((r) => `${r.app} ${r.version} (#${r.idx})`).join(", ")} is in the log but not on the approved list.
        </div>
      )}
      <Card className="!p-0 overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-4 p-6">
          <h2 className="text-2xl font-medium">{rows.length} releases</h2>
          <button onClick={() => dlg.current?.showModal()} className="flex items-center gap-2 rounded-full bg-ok px-6 py-3 text-lg font-semibold text-bg transition hover:scale-105 active:scale-95"><Plus className="size-5" /> Publish</button>
        </div>
        <div className="overflow-x-auto overflow-y-hidden">
          <table className="w-full min-w-[56rem] text-left text-lg">
            <thead className="border-y border-line text-sm uppercase tracking-wider text-mute">
              <tr>{["App", "Version", "Platform", "SHA-256", "Log #", "Approved"].map((h) => <th key={h} className="px-6 py-4 font-medium">{h}</th>)}</tr>
            </thead>
            <tbody>
              {rows.map((r, i) => { const P = Icon[r.platform]; return (
                <tr key={r.idx} style={{ animationDelay: `${i * 60}ms` }} className="animate-rise border-b border-line/60 transition hover:bg-line/40">
                  <td className="px-6 py-5 font-mono">{r.app}</td>
                  <td className="px-6 py-5 font-mono">{r.version}</td>
                  <td className="px-6 py-5"><span className="flex items-center gap-2 text-mute"><P className="size-5" />{r.platform}</span></td>
                  <td className="px-6 py-5 font-mono text-mute" title={r.sha256}>{short(r.sha256)}</td>
                  <td className="px-6 py-5 font-mono">#{r.idx}</td>
                  <td className="px-6 py-5">
                    <button onClick={() => setRows((x) => x.map((y) => y.idx === r.idx ? { ...y, approved: !y.approved } : y))} aria-label="toggle approved">
                      {r.approved ? <Badge tone="ok"><ShieldCheck className="size-4" />approved</Badge> : <Badge tone="bad"><ShieldAlert className="size-4" />unapproved</Badge>}
                    </button>
                  </td>
                </tr>); })}
            </tbody>
          </table>
        </div>
      </Card>
      <dialog ref={dlg} onClick={(e) => e.target === dlg.current && dlg.current.close()} className="m-auto w-[min(90vw,32rem)] rounded-3xl border border-line bg-panel p-0 text-ink backdrop:bg-black/70 backdrop:backdrop-blur-sm open:animate-rise">
        <form action={publish} className="grid gap-5 p-8">
          <h3 className="text-3xl font-semibold">Publish release</h3>
          <input name="app" defaultValue="notepad-minus" required placeholder="app" className="rounded-2xl border border-line bg-bg px-5 py-4 text-lg outline-none focus:border-ok" />
          <input name="version" defaultValue="2.1.2" required pattern="\d+\.\d+\.\d+" placeholder="semver" className="rounded-2xl border border-line bg-bg px-5 py-4 text-lg outline-none focus:border-ok" />
          <select name="platform" className="rounded-2xl border border-line bg-bg px-5 py-4 text-lg outline-none focus:border-ok">{platforms.map((p) => <option key={p}>{p}</option>)}</select>
          <button className="rounded-full bg-ok py-4 text-lg font-semibold text-bg transition hover:scale-[1.02] active:scale-95">Sign &amp; append to log</button>
        </form>
      </dialog>
    </>
  );
}
