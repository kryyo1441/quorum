import { Clock3, ShieldCheck } from "lucide-react";
import { Badge, Card, Title } from "@/components/ui";
import { Merkle } from "@/components/merkle";
import { getHeads, getLeaves, getLogKey } from "@/lib/api";
import { short } from "@/lib/format";

export const dynamic = "force-dynamic";
const WITNESSES = ["w1", "w2", "w3"];

export default async function Log() {
  const [leaves, heads, key] = await Promise.all([getLeaves(), getHeads(), getLogKey()]);
  const sub = "An append-only Merkle tree. Pick a leaf to fetch its proof and verify it right here in the browser.";
  if (!leaves || !heads || !key) return (<><Title sub={sub}>Log explorer</Title><Card><Badge tone="bad">log-server unreachable</Badge></Card></>);
  if (heads.length === 0) return (<><Title sub={sub}>Log explorer</Title><Card><Badge tone="mute">empty log</Badge><p className="mt-4 text-lg text-mute">Publish a release to create the first signed head.</p></Card></>);
  const latest = heads[heads.length - 1];
  return (
    <>
      <Title sub={sub}>Log explorer</Title>
      <Merkle leaves={leaves} head={latest} logKey={key} />
      <h2 className="mb-5 mt-14 text-3xl font-medium">Signed tree heads</h2>
      <div className="grid gap-6 [grid-template-columns:repeat(auto-fill,minmax(20rem,1fr))]">
        {[...heads].reverse().map((s, i) => (
          <Card key={s.treeSize} delay={i * 60}>
            <div className="text-5xl font-semibold tabular-nums">{s.treeSize}<span className="ml-2 text-base font-normal text-mute">leaves</span></div>
            <div className="mt-3 font-mono text-sm text-mute">{short(s.rootHash, 12)}</div>
            <div className="mt-5 flex flex-wrap gap-2">
              {WITNESSES.map((w) => s.cosigs.some((c) => c.witnessId === w)
                ? <Badge key={w} tone="ok"><ShieldCheck className="size-4" />{w}</Badge>
                : <Badge key={w} tone="mute"><Clock3 className="size-4" />{w} pending</Badge>)}
            </div>
          </Card>
        ))}
      </div>
    </>
  );
}
