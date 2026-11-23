export const platforms = ["win-x64", "mac-arm64", "linux-x64"] as const;
export type Platform = (typeof platforms)[number];
export type Release = { idx: number; app: string; version: string; platform: Platform; sha256: string; publishedAt: string; approved: boolean };
export const short = (h: string, n = 8) => `${h.slice(0, n)}…${h.slice(-4)}`;
