"use client";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Head } from "@/lib/api";

/** Tree size at each signed head, so an append-only log reads as a line that only goes up. */
export function GrowthChart({ heads }: { heads: Head[] }) {
  const data = heads.map((h) => ({ at: h.timestamp.slice(11, 19), size: h.treeSize, cosigs: h.cosigs.length }));
  return (
    <div className="h-64 w-full">
      <ResponsiveContainer>
        <AreaChart data={data} margin={{ top: 8, right: 16, left: -8, bottom: 0 }}>
          <defs><linearGradient id="grow" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#b9a2f2" stopOpacity={0.5} /><stop offset="1" stopColor="#b9a2f2" stopOpacity={0} /></linearGradient></defs>
          <CartesianGrid stroke="#242030" vertical={false} />
          <XAxis dataKey="at" stroke="#8d879c" tickLine={false} />
          <YAxis allowDecimals={false} stroke="#8d879c" tickLine={false} />
          <Tooltip contentStyle={{ background: "#121019", border: "1px solid #242030", borderRadius: 12, color: "#ede9f6" }} formatter={(v, k) => [v, k === "size" ? "leaves" : "cosignatures"]} />
          <Area type="stepAfter" dataKey="size" stroke="#b9a2f2" strokeWidth={2} fill="url(#grow)" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
