import type { ReleaseEntry } from "@uw/shared";

export type Leaf = { idx: number; entry: ReleaseEntry; leafHash: string };

/** Append-only leaf storage. No update/delete on purpose. */
export interface LogStore {
  append(entry: ReleaseEntry, leafHash: string): Promise<Leaf>;
  all(): Promise<Leaf[]>;
}

export function memoryStore(): LogStore {
  const rows: Leaf[] = [];
  return {
    append: async (entry, leafHash) => { const l = { idx: rows.length, entry, leafHash }; rows.push(l); return l; },
    all: async () => [...rows],
  };
}
