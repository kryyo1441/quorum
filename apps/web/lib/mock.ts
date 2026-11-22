// MOCK DATA until log-server exists (Day 1 shell). Shapes follow SPEC §6.
const hex = (seed: number) => { let s = seed * 2654435761 >>> 0, o = ""; for (let i = 0; i < 64; i++) { s = (s * 1664525 + 1013904223) >>> 0; o += (s >>> 28).toString(16); } return o; };
export const platforms = ["win-x64", "mac-arm64", "linux-x64"] as const;
export type Platform = (typeof platforms)[number];
export type Release = { idx: number; app: string; version: string; platform: Platform; sha256: string; publishedAt: string; approved: boolean };
const v = ["2.0.0", "2.0.1", "2.0.1", "2.0.2", "2.1.0", "2.1.0", "2.1.0", "2.1.1"];
export const releases: Release[] = v.map((version, i) => ({
  idx: i, app: "notepad-minus", version, platform: platforms[i % 3], sha256: hex(i + 1),
  publishedAt: new Date(Date.UTC(2026, 10, 1 + i * 2, 9, 30)).toISOString(), approved: i !== 6,
}));
export const leafHashes = releases.map((r) => hex(r.idx + 100));
export const witnesses = ["w1", "w2", "w3"];
export const sths = [2, 3, 4, 5, 6, 8].map((treeSize, i) => ({ treeSize, rootHash: hex(treeSize + 500), timestamp: new Date(Date.UTC(2026, 10, 3 + i * 2, 9, 31)).toISOString(), cosigs: witnesses.slice(0, i === 3 ? 2 : 3) }));
export const short = (h: string, n = 8) => `${h.slice(0, n)}…${h.slice(-4)}`;

export type Scenario = { id: number; name: string; expect: string };
export const scenarios: Scenario[] = [
  { id: 1, name: "Update server serves target a different binary, same manifest", expect: "HASH_MISMATCH" },
  { id: 2, name: "Different binary with a forged manifest", expect: "BAD_VENDOR_SIG" },
  { id: 3, name: "Stolen vendor key, release signed but not logged", expect: "NOT_IN_LOG" },
  { id: 4, name: "Stolen vendor key, malicious release logged", expect: "UNAPPROVED_RELEASE" },
  { id: 5, name: "Log shows target a forked tree (split view)", expect: "INSUFFICIENT_COSIGS" },
  { id: 6, name: "Replay of an old vulnerable release (downgrade)", expect: "STALE_STH" },
  { id: 7, name: "One witness compromised, cosigns anything", expect: "INSUFFICIENT_COSIGS" },
  { id: 8, name: "Log or witnesses unreachable", expect: "NOT_IN_LOG / INSUFFICIENT_COSIGS" },
  { id: 9, name: "Stored log leaf tampered in Postgres", expect: "BAD_INCLUSION_PROOF" },
  { id: 10, name: "Two clients told different hashes for one version", expect: "HASH_MISMATCH" },
];
export const alerts = [
  { id: "a1", kind: "HASH_MISMATCH", app: "notepad-minus", version: "2.1.0", platform: "win-x64", raisedBy: "w2", raisedAt: "2026-11-21T14:02:11Z",
    evidence: { observationA: { client: "pseud-3f9a", sha256: releases[5].sha256 }, observationB: { client: "pseud-b710", sha256: "e".repeat(64) } } },
];
