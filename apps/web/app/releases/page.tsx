import { Badge, Card, Title } from "@/components/ui";
import { ReleasesTable } from "@/components/releases-table";
import { getLeaves, getMonitorAlerts } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function Releases() {
  const [leaves, monitor] = await Promise.all([getLeaves(), getMonitorAlerts()]);
  // approved = the vendor monitor has NOT flagged it. null = monitor unreachable, so approval status is unknown (shown as such, not as approved).
  const unapproved = monitor && monitor.filter((a) => a.kind === "UNAPPROVED_RELEASE").map((a) => (a.evidence as { idx: number }).idx);
  return (
    <>
      <Title sub="Everything the vendor has signed and appended to the public log.">Vendor console</Title>
      {leaves
        ? <ReleasesTable unapproved={unapproved} rows={leaves.map((l) => ({ idx: l.idx, app: l.entry.app, version: l.entry.version, platform: l.entry.platform, sha256: l.entry.sha256, publishedAt: l.entry.publishedAt }))} />
        : <Card><Badge tone="bad">log-server unreachable</Badge><p className="mt-4 text-lg text-mute">Start it with <code>docker compose up</code> or <code>pnpm --filter @uw/log-server dev</code>.</p></Card>}
    </>
  );
}
