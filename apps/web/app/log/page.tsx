import { ShieldCheck, ShieldAlert } from "lucide-react";
import { Badge, Card, Title } from "@/components/ui";
import { Merkle } from "@/components/merkle";
import { short, sths, witnesses } from "@/lib/mock";

export default function Log() {
  return (
    <>
      <Title sub="An append-only Merkle tree. Pick a leaf to see the path that proves it is in the log.">Log explorer</Title>
      <Merkle />
      <h2 className="mb-5 mt-14 text-3xl font-medium">Signed tree heads</h2>
      <div className="grid gap-6 [grid-template-columns:repeat(auto-fill,minmax(20rem,1fr))]">
        {[...sths].reverse().map((s, i) => (
          <Card key={s.treeSize} delay={i * 80}>
            <div className="text-5xl font-semibold tabular-nums">{s.treeSize}<span className="ml-2 text-base font-normal text-mute">leaves</span></div>
            <div className="mt-3 font-mono text-sm text-mute">{short(s.rootHash, 12)}</div>
            <div className="mt-5 flex flex-wrap gap-2">
              {witnesses.map((w) => s.cosigs.includes(w)
                ? <Badge key={w} tone="ok"><ShieldCheck className="size-4" />{w}</Badge>
                : <Badge key={w} tone="bad"><ShieldAlert className="size-4" />{w}</Badge>)}
            </div>
          </Card>
        ))}
      </div>
    </>
  );
}
