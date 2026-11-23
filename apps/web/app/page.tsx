import { Eye, FileCheck2, GitBranch, ShieldAlert, Server } from "lucide-react";
import { Card, Title, Badge } from "@/components/ui";
import { CountUp } from "@/components/count-up";
import { LiveFeed } from "@/components/live-feed";
import { getLeaves, witnessesOnline } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function Overview() {
  const [leaves, online] = await Promise.all([getLeaves(), witnessesOnline()]);
  const n = leaves?.length ?? 0;
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
      <LiveFeed />
    </>
  );
}
