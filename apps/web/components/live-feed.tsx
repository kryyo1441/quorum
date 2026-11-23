"use client";
import { useEffect, useState } from "react";
import { Eye, ShieldAlert, Swords } from "lucide-react";
import { Badge, Card } from "./ui";

type Ev = { id: number; at: string; type: string; text: string; tone: "ok" | "bad" | "mute" };
type Stats = { clientsVerified: number; clientsBlocked: number; alerts: number; attacks: number };

/** Subscribes to the demo server's event stream: everything shown here was observed from the real services. */
export function LiveFeed() {
  const [events, setEvents] = useState<Ev[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [down, setDown] = useState(false);

  useEffect(() => {
    const es = new EventSource("/api/demo/events");
    es.addEventListener("ev", (m) => { setDown(false); const e: Ev = JSON.parse((m as MessageEvent).data); setEvents((x) => (x.some((y) => y.id === e.id) ? x : [e, ...x].slice(0, 40))); });
    es.addEventListener("stats", (m) => setStats(JSON.parse((m as MessageEvent).data)));
    es.onerror = () => setDown(true); // EventSource reconnects by itself
    return () => es.close();
  }, []);

  const kpi = [
    { label: "Clients verified", n: stats?.clientsVerified, Icon: Eye },
    { label: "Clients blocked", n: stats?.clientsBlocked, Icon: ShieldAlert },
    { label: "Alerts raised", n: stats?.alerts, Icon: ShieldAlert },
    { label: "Attacks armed", n: stats?.attacks, Icon: Swords },
  ];
  return (
    <>
      <div className="mt-6 grid gap-6 [grid-template-columns:repeat(auto-fit,minmax(14rem,1fr))]">
        {kpi.map(({ label, n, Icon }, i) => (
          <Card key={label} delay={600 + i * 80}>
            <Icon className="size-5 text-mute" />
            <div className="mt-4 text-5xl tabular-nums">{n ?? "–"}</div>
            <div className="mt-1 text-mute">{label}</div>
          </Card>))}
      </div>
      <Card className="mt-6" delay={900}>
        <div className="mb-4 flex items-center justify-between"><h2 className="text-2xl">Live event feed</h2>{down && <Badge tone="bad">demo server unreachable</Badge>}</div>
        {events.length === 0 && !down && <p className="text-lg text-mute">Nothing yet. Publish a release or roll out the fleet.</p>}
        <ul className="divide-y divide-line">
          {events.map((e) => (
            <li key={e.id} className="animate-rise flex flex-wrap items-center gap-x-5 gap-y-1 py-3 text-lg">
              <Badge tone={e.tone}>{e.type}</Badge><span>{e.text}</span><span className="ml-auto font-mono text-sm text-mute">{e.at.slice(11, 19)}</span>
            </li>))}
        </ul>
      </Card>
    </>
  );
}
