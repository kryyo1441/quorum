"use client";
import { useRouter } from "next/navigation";
import { useEffect } from "react";
/** Re-runs the server component every `ms` so live data (heads, alerts) stays current without a full reload. */
export function AutoRefresh({ ms = 3000 }: { ms?: number }) { const r = useRouter(); useEffect(() => { const t = setInterval(() => r.refresh(), ms); return () => clearInterval(t); }, [r, ms]); return null; }
