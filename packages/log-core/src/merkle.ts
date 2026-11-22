// RFC 6962 / RFC 9162 Merkle tree. Hashes are lowercase hex. Browser-safe: noble only, no node:crypto or Buffer.
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";

const H = (prefix: number, ...parts: Uint8Array[]) => bytesToHex(sha256(concatBytes(Uint8Array.of(prefix), ...parts)));

export const emptyRoot = () => bytesToHex(sha256(new Uint8Array()));
export const hashLeaf = (data: Uint8Array) => H(0x00, data);
export const hashChildren = (l: string, r: string) => H(0x01, hexToBytes(l), hexToBytes(r));

/** Largest power of two strictly less than n (n >= 2). The RFC split point k: k < n <= 2k. */
const split = (n: number) => 2 ** Math.floor(Math.log2(n - 1));

/** MTH over already-hashed leaves. */
export function rootHash(leaves: string[]): string {
  if (leaves.length === 0) return emptyRoot();
  if (leaves.length === 1) return leaves[0];
  const k = split(leaves.length);
  return hashChildren(rootHash(leaves.slice(0, k)), rootHash(leaves.slice(k)));
}

/** Audit path for leaf `m` in a tree of `leaves` (RFC 9162 §2.1.3.1). */
export function inclusionPath(leaves: string[], m: number): string[] {
  const n = leaves.length;
  if (!(m >= 0 && m < n)) throw new RangeError("leaf index out of range");
  if (n === 1) return [];
  const k = split(n);
  return m < k ? [...inclusionPath(leaves.slice(0, k), m), rootHash(leaves.slice(k))]
               : [...inclusionPath(leaves.slice(k), m - k), rootHash(leaves.slice(0, k))];
}

/** RFC 9162 §2.1.3.2. Returns false (never throws) on any mismatch or malformed input. */
export function verifyInclusion(leafHash: string, index: number, size: number, path: string[], root: string): boolean {
  try {
    if (!Number.isInteger(index) || !Number.isInteger(size) || index < 0 || index >= size) return false;
    let fn = index, sn = size - 1, r = leafHash;
    for (const p of path) {
      if (sn === 0) return false;
      if ((fn & 1) === 1 || fn === sn) {
        r = hashChildren(p, r);
        if ((fn & 1) === 0) while ((fn & 1) === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
      } else r = hashChildren(r, p);
      fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
    }
    return sn === 0 && r === root;
  } catch { return false; }
}

/** Consistency proof between the first m leaves and all n leaves (RFC 9162 §2.1.4.1). Requires 1 <= m <= n. */
export function consistencyPath(leaves: string[], m: number): string[] {
  const n = leaves.length;
  if (!(m >= 1 && m <= n)) throw new RangeError("need 1 <= m <= n");
  const sub = (m: number, d: string[], b: boolean): string[] => {
    const n = d.length;
    if (m === n) return b ? [] : [rootHash(d)];
    const k = split(n);
    return m <= k ? [...sub(m, d.slice(0, k), b), rootHash(d.slice(k))]
                  : [...sub(m - k, d.slice(k), false), rootHash(d.slice(0, k))];
  };
  return sub(m, leaves, true);
}

/** RFC 9162 §2.1.4.2. Returns false (never throws) on any mismatch or malformed input. */
export function verifyConsistency(m: number, n: number, rootM: string, rootN: string, path: string[]): boolean {
  try {
    if (!Number.isInteger(m) || !Number.isInteger(n) || m < 1 || m > n) return false;
    if (m === n) return path.length === 0 && rootM === rootN;
    if (path.length === 0) return false;
    const p = (m & (m - 1)) === 0 ? [rootM, ...path] : path; // m is a power of two: its root is the first node
    let fn = m - 1, sn = n - 1;
    while ((fn & 1) === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    let fr = p[0], sr = p[0];
    for (const c of p.slice(1)) {
      if (sn === 0) return false;
      if ((fn & 1) === 1 || fn === sn) {
        fr = hashChildren(c, fr); sr = hashChildren(c, sr);
        if ((fn & 1) === 0) while ((fn & 1) === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
      } else sr = hashChildren(sr, c);
      fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
    }
    return fr === rootM && sr === rootN && sn === 0;
  } catch { return false; }
}
