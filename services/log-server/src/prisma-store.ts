import { PrismaClient } from "@prisma/client";
import type { ReleaseEntry, STH } from "@uw/shared";
import type { LogStore } from "./store.js";

export function prismaStore(logId: string, db = new PrismaClient()): LogStore {
  const row = (r: { idx: number; entry: unknown; leafHash: string }) => ({ idx: r.idx, entry: r.entry as ReleaseEntry, leafHash: r.leafHash });
  const sth = (r: { treeSize: number; rootHash: string; timestamp: string; logSig: string; cosigs: unknown }): STH => ({ logId, treeSize: r.treeSize, rootHash: r.rootHash, timestamp: r.timestamp, logSig: r.logSig, cosigs: r.cosigs as STH["cosigs"] });
  return {
    // Advisory lock serialises appends so leaf indexes are gapless and unique.
    append: (entry, leafHash) => db.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(1)`;
      const idx = await tx.leaf.count();
      return row(await tx.leaf.create({ data: { idx, entry: entry as object, leafHash } }));
    }),
    all: async () => (await db.leaf.findMany({ orderBy: { idx: "asc" } })).map(row),
    saveSth: async (s) => { await db.sth.createMany({ data: [{ treeSize: s.treeSize, rootHash: s.rootHash, timestamp: s.timestamp, logSig: s.logSig, cosigs: s.cosigs as object[] }], skipDuplicates: true }); },
    sthAt: async (n) => { const r = await db.sth.findUnique({ where: { treeSize: n } }); return r ? sth(r) : undefined; },
    allSths: async () => (await db.sth.findMany({ orderBy: { treeSize: "asc" } })).map(sth),
    setCosigs: async (n, cosigs) => { await db.sth.update({ where: { treeSize: n }, data: { cosigs: cosigs as object[] } }); },
    latestSth: async () => { const r = await db.sth.findFirst({ orderBy: { treeSize: "desc" } }); return r ? sth(r) : undefined; },
  };
}
