import type { ReleaseEntry, STH } from "@uw/shared";

export type Leaf = { idx: number; entry: ReleaseEntry; leafHash: string };

/** Append-only storage of leaves and one signed head per tree size. No update/delete on purpose. */
export interface LogStore {
  append(entry: ReleaseEntry, leafHash: string): Promise<Leaf>;
  all(): Promise<Leaf[]>;
  saveSth(sth: STH): Promise<void>;   // idempotent per treeSize
  sthAt(size: number): Promise<STH | undefined>;
  allSths(): Promise<STH[]>;          // ascending by treeSize, one query
  latestSth(): Promise<STH | undefined>;
  setCosigs(size: number, cosigs: STH["cosigs"]): Promise<void>; // replaces the cosig list of one head (callers serialise the read-modify-write)
}

export function memoryStore(): LogStore {
  const rows: Leaf[] = [], heads = new Map<number, STH>();
  return {
    append: async (entry, leafHash) => { const l = { idx: rows.length, entry, leafHash }; rows.push(l); return l; },
    all: async () => [...rows],
    saveSth: async (s) => { if (!heads.has(s.treeSize)) heads.set(s.treeSize, s); },
    sthAt: async (n) => heads.get(n),
    allSths: async () => [...heads.values()].sort((a, b) => a.treeSize - b.treeSize),
    setCosigs: async (n, cosigs) => { const h = heads.get(n); if (h) heads.set(n, { ...h, cosigs }); },
    latestSth: async () => [...heads.values()].reduce<STH | undefined>((m, h) => (!m || h.treeSize > m.treeSize ? h : m), undefined),
  };
}
