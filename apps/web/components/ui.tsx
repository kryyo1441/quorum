import type { ReactNode } from "react";

export function Card({ children, className = "", delay = 0 }: { children: ReactNode; className?: string; delay?: number }) {
  return (
    <div style={{ animationDelay: `${delay}ms` }}
      className={`animate-rise rounded-3xl border border-line bg-panel/80 p-6 backdrop-blur transition duration-300 hover:-translate-y-0.5 hover:border-ok/40 hover:shadow-[0_0_60px_-20px_var(--color-ok)] ${className}`}>
      {children}
    </div>
  );
}

export function Badge({ tone, children }: { tone: "ok" | "bad" | "mute"; children: ReactNode }) {
  const c = { ok: "text-ok border-ok/40 bg-ok/10", bad: "text-bad border-bad/40 bg-bad/10", mute: "text-mute border-line" }[tone];
  return <span className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium ${c}`}>{children}</span>;
}

export const Title = ({ children, sub }: { children: ReactNode; sub?: string }) => (
  <header className="animate-rise mb-10">
    <h1 className="text-5xl font-semibold tracking-tight sm:text-6xl">{children}</h1>
    {sub && <p className="mt-3 max-w-2xl text-lg text-mute">{sub}</p>}
  </header>
);
