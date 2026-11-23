import { Eye, FileCheck2, GitBranch, ShieldAlert, Server } from "lucide-react";
import { Card, Title, Badge } from "@/components/ui";
import { CountUp } from "@/components/count-up";
import { getLeaves, witnessesOnline } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function Overview() {
  const [leaves, online] = await Promise.all([getLeaves(), witnessesOnline()]);
  const n = leaves?.length ?? 0;
  // ponytail: clients verified and attacks blocked stay 0 until fleet/attack runs are recorded server-side.
  const kpis = [
    { label: "Releases logged", n, Icon: FileCheck2 },
    { label: "Tree size", n, Icon: GitBranch },
    { label: "Witnesses online", n: online, Icon: Server },
  ];
  return (
    <>
      <Title sub="An update installs only if everyone was offered the same file, and it sits in a public log cosigned by independent witnesses.">
        Trust the log,<br /><span className="bg-accent bg-clip-text italic text-transparent">not the server.</span>
      </Title>
      <div className="grid gap-6 [grid-template-columns:repeat(auto-fit,minmax(18rem,1fr))]">
        {kpis.map(({ label, n, Icon }, i) => (
          <Card key={label} delay={120 + i * 90}>
            <Icon className="size-6 text-mute" />
            <div className="mt-6 text-7xl font-semibold tabular-nums tracking-tight"><CountUp to={n} /></div>
            <div className="mt-2 text-mute">{label}</div>
          </Card>
        ))}
      </div>
      <Card className="mt-6" delay={600}>
        <div className="mb-4 flex items-center justify-between"><h2 className="text-2xl font-medium">Live event feed</h2>{!leaves && <Badge tone="bad">log-server unreachable</Badge>}</div>
        <ul className="divide-y divide-line">
          {(leaves ?? []).slice(-5).reverse().map((r) => (
            <li key={r.idx} className="flex flex-wrap items-center gap-x-6 gap-y-2 py-4 text-lg">
              <Badge tone="ok">logged</Badge>
              <span className="font-mono">{r.entry.app} {r.entry.version}</span><span className="text-mute">{r.entry.platform}</span>
              <span className="ml-auto text-sm text-mute">leaf #{r.idx}</span>
            </li>
          ))}
        </ul>
      </Card>
    </>
  );
}
