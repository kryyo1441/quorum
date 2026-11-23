// Vendor monitor, SPEC §9. Tails the log and raises UNAPPROVED_RELEASE for any entry that is not on the approved list.
import { leafHashOfEntry, verifyConsistency, verifyEntry, verifyLogSig } from "@uw/log-core";
import type { ReleaseEntry, SplitViewAlert, STH } from "@uw/shared";

export type Approved = { app: string; version: string; platform: string; sha256: string };
export type MonitorDeps = {
  entries(): Promise<{ idx: number; entry: ReleaseEntry; leafHash: string }[]>;
  head(): Promise<STH>;
  consistency(from: number, to: number): Promise<string[]>;
  now(): Date;
};
export type MonitorConfig = { logId: string; logPublicKey: string; vendorPublicKeys: Record<string, string> };

export class Monitor {
  private readonly approved = new Set<string>();
  private readonly raised = new Set<string>();
  private lastHead?: STH;
  readonly alerts: SplitViewAlert[] = [];
  constructor(private readonly cfg: MonitorConfig, private readonly d: MonitorDeps) {}

  approve(r: Approved) { this.approved.add(`${r.app}\0${r.version}\0${r.platform}\0${r.sha256}`); }

  /** One poll. Does not trust the log's own leaf hashes: recomputes them from the entries, and checks every head is consistent with the last one.
   *  Returns the NEW alerts. Throws if the log is unreachable (the caller retries; nothing is silently skipped). */
  async poll(): Promise<SplitViewAlert[]> {
    const head = await this.d.head(), out: SplitViewAlert[] = [];
    const add = (kind: SplitViewAlert["kind"], e: { app: string; version: string; platform: string }, evidence: Record<string, unknown>, key: string) => {
      if (this.raised.has(key)) return;
      this.raised.add(key);
      const a: SplitViewAlert = { kind, app: e.app, version: e.version, platform: e.platform, evidence, raisedBy: "monitor", raisedAt: this.d.now().toISOString() };
      this.alerts.push(a); out.push(a);
    };
    if (head.logId !== this.cfg.logId || !verifyLogSig(head, this.cfg.logPublicKey)) throw new Error("log head is not signed by the pinned log key");
    if (this.lastHead && head.treeSize >= this.lastHead.treeSize) {
      if (head.treeSize === this.lastHead.treeSize) { if (head.rootHash !== this.lastHead.rootHash) add("INCONSISTENT_STH", { app: "*", version: "*", platform: "*" }, { headA: this.lastHead, headB: head }, `fork:${head.rootHash}`); }
      else if (!verifyConsistency(this.lastHead.treeSize, head.treeSize, this.lastHead.rootHash, head.rootHash, await this.d.consistency(this.lastHead.treeSize, head.treeSize)))
        add("INCONSISTENT_STH", { app: "*", version: "*", platform: "*" }, { headA: this.lastHead, headB: head }, `fork:${head.rootHash}`);
    } else if (this.lastHead) add("INCONSISTENT_STH", { app: "*", version: "*", platform: "*" }, { headA: this.lastHead, headB: head, note: "tree shrank" }, `shrink:${head.treeSize}`);
    if (!this.lastHead || head.treeSize >= this.lastHead.treeSize) this.lastHead = head;

    for (const l of (await this.d.entries()).slice(0, head.treeSize)) {
      const e = l.entry, leafHash = leafHashOfEntry(e);
      if (leafHash !== l.leafHash) { add("NOT_IN_LOG", e, { idx: l.idx, claimed: l.leafHash, recomputed: leafHash }, `tamper:${l.idx}`); continue; }
      const vk = this.cfg.vendorPublicKeys[e.vendorKeyId];
      const signed = vk !== undefined && verifyEntry(e, vk);
      if (!signed || !this.approved.has(`${e.app}\0${e.version}\0${e.platform}\0${e.sha256}`))
        add("UNAPPROVED_RELEASE", e, { idx: l.idx, leafHash, sha256: e.sha256, vendorKeyId: e.vendorKeyId, validVendorSig: signed }, `rel:${leafHash}`);
    }
    return out;
  }
}
