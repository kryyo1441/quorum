"use client";
import { useEffect, useState } from "react";

export function CountUp({ to, ms = 1200 }: { to: number; ms?: number }) {
  const [n, setN] = useState(0);
  useEffect(() => {
    let raf = 0; const t0 = performance.now();
    const step = (t: number) => { const p = Math.min((t - t0) / ms, 1); setN(Math.round(to * (1 - (1 - p) ** 3))); if (p < 1) raf = requestAnimationFrame(step); };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [to, ms]);
  return <>{n}</>;
}
