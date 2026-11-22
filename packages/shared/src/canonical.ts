/** Canonical JSON: sorted keys, no whitespace, UTF-8 (SPEC §6). */
export function canonicalize(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).sort().filter((k) => o[k] !== undefined)
    .map((k) => `${JSON.stringify(k)}:${canonicalize(o[k])}`).join(",")}}`;
}
export const canonicalBytes = (v: unknown) => new TextEncoder().encode(canonicalize(v));
