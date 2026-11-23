// End-to-end check against a RUNNING stack (docker compose up, or the dev stack), through the demo server: pnpm --filter @uw/demo smoke
// Asserts what the dashboard shows for attacks 1, 5, 4 and 9, then that Reset restores a clean system. Exits non-zero on the first surprise.
const DEMO = process.env.DEMO_URL ?? "http://localhost:4200", MONITOR = process.env.MONITOR_URL ?? "http://localhost:4300";
const WITNESSES = (process.env.WITNESS_URLS ?? "http://localhost:4101,http://localhost:4102,http://localhost:4103").split(",");
type R = { id: string; state: "verified" | "blocked"; reason?: string; version: string };
let failed = 0;
const check = (ok: boolean, what: string) => { console.log(`${ok ? "ok  " : "FAIL"} ${what}`); if (!ok) failed++; };
const post = async (p: string, b: unknown = {}) => { const r = await fetch(`${DEMO}${p}`, { method: "POST", body: JSON.stringify(b) }); if (!r.ok) throw new Error(`${p}: ${r.status} ${await r.text()}`); };
const j = async <T>(u: string) => (await fetch(u)).json() as Promise<T>;
async function fleet(n = 12): Promise<R[]> {
  const r = await fetch(`${DEMO}/fleet/stream?n=${n}`), out: R[] = [];
  let ev = "";
  for (const l of (await r.text()).split("\n")) { if (l.startsWith("event:")) ev = l.slice(7).trim(); else if (l.startsWith("data:") && ev === "result") out.push(JSON.parse(l.slice(6))); }
  return out.sort((a, b) => Number(a.id.slice(1)) - Number(b.id.slice(1)));
}
const until = async (f: () => Promise<boolean>, ms = 15000) => { const end = Date.now() + ms; while (Date.now() < end) { if (await f()) return true; await new Promise((r) => setTimeout(r, 300)); } return false; };
const alertKinds = async () => (await Promise.all([...WITNESSES, MONITOR].map((u) => j<{ kind: string }[]>(`${u}/alerts`).catch(() => [])))).flat().map((a) => a.kind);

await post("/reset");
let r = await fleet();
check(r.length === 12 && r.every((x) => x.state === "verified"), `clean rollout: ${r.filter((x) => x.state === "verified").length}/12 verified`);

await post("/attack1", { clientId: "c7" }); r = await fleet();
check(r[6].reason === "HASH_MISMATCH" && r.filter((x) => x.state === "verified").length === 11, `attack 1: c7 ${r[6].reason}, others verified ${r.filter((x) => x.state === "verified").length}/11`);
check((await alertKinds()).filter((k) => k === "HASH_MISMATCH").length >= 3, "attack 1: every witness raised HASH_MISMATCH");

await post("/reset"); r = await fleet();
check(r.every((x) => x.state === "verified") && (await alertKinds()).length === 0, "reset: fleet clean again and all alerts cleared");

await post("/attacks/fork", { clientId: "c3" }); r = await fleet();
check(r[2].reason === "INSUFFICIENT_COSIGS", `attack 5: c3 blocked ${r[2].reason}`);
check(await until(async () => (await alertKinds()).filter((k) => k === "INCONSISTENT_STH").length >= 3), "attack 5: every witness raised INCONSISTENT_STH from the forwarded head");
r = await fleet();
check(r.filter((x) => x.reason === "SPLIT_VIEW" || x.reason === "INSUFFICIENT_COSIGS").length === 12, "attack 5: once the fork is proven, every client fails closed");

await post("/reset"); r = await fleet();
check(r.every((x) => x.state === "verified"), "reset after attack 5: fleet clean");

await post("/attacks/stolen-key");
check(await until(async () => (await j<{ kind: string; version: string }[]>(`${MONITOR}/alerts`)).some((a) => a.kind === "UNAPPROVED_RELEASE" && a.version === "2.2.0"), 10000), "attack 4: monitor raised UNAPPROVED_RELEASE for 2.2.0");
r = await fleet();
check(r.every((x) => x.state === "verified" && x.version === "2.2.0"), "attack 4: clients accept it (detected, not prevented)");

await post("/reset"); r = await fleet();
check(r.every((x) => x.state === "verified" && x.version === "2.1.0"), "reset after attack 4: the malicious release is taken down");

const tamper = await fetch(`${DEMO}/attacks/tamper`, { method: "POST", body: "{}" });
if (!tamper.ok) console.log(`skip attack 9: ${(await tamper.json() as { error: string }).error}`);
else {
  check(await until(async () => (await j<{ kind: string }[]>(`${MONITOR}/alerts`)).some((a) => a.kind === "INCONSISTENT_STH" || a.kind === "NOT_IN_LOG")), "attack 9: monitor noticed the rewritten leaf");
  r = await fleet();
  check(r.every((x) => x.state === "blocked") || r.some((x) => x.state === "blocked"), `attack 9: clients blocked (${[...new Set(r.map((x) => x.reason))].join(",")})`);
  await post("/reset"); r = await fleet();
  check(r.every((x) => x.state === "verified"), "reset after attack 9: the row is restored and the fleet is clean");
}
await post("/reset");
console.log(failed ? `\n${failed} check(s) FAILED` : "\nall checks passed");
process.exit(failed ? 1 : 0);
