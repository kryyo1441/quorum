import type { ReleaseEntry, STH } from "@uw/shared";

export type Leaf = { idx: number; entry: ReleaseEntry; leafHash: string };

/** Append-only storage of leaves and one signed head per tree size. No update/delete on purpose. */
export interface LogStore {
  append(entry: ReleaseEntry, leafHash: string): Promise<Leaf>;
  all(): Promise<Leaf[]>;
  saveSth(sth: STH): Promise<void>;   // idempotent per treeSize
  sthAt(size: number): Promise<STH | undefined>;
  latestSth(): Promise<STH | undefined>;
}

export function memoryStore(): LogStore {
  const rows: Leaf[] = [], heads = new Map<number, STH>();
  return {
    append: async (entry, leafHash) => { const l = { idx: rows.length, entry, leafHash }; rows.push(l); return l; },
    all: async () => [...rows],
    saveSth: async (s) => { if (!heads.has(s.treeSize)) heads.set(s.treeSize, s); },
    sthAt: async (n) => heads.get(n),
    latestSth: async () => heads.get(Math.max(0, ...heads.keys())),
  };
}
