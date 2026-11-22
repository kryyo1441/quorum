import { PrismaClient } from "@prisma/client";
import type { ReleaseEntry } from "@uw/shared";
import type { LogStore } from "./store.js";

export function prismaStore(db = new PrismaClient()): LogStore {
  const row = (r: { idx: number; entry: unknown; leafHash: string }) => ({ idx: r.idx, entry: r.entry as ReleaseEntry, leafHash: r.leafHash });
  return {
    // Advisory lock serialises appends so leaf indexes are gapless and unique.
    append: (entry, leafHash) => db.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(1)`;
      const idx = await tx.leaf.count();
      return row(await tx.leaf.create({ data: { idx, entry: entry as object, leafHash } }));
    }),
    all: async () => (await db.leaf.findMany({ orderBy: { idx: "asc" } })).map(row),
  };
}
