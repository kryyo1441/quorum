import { attack1, clientIds, reset, runFleet, seed, type Env } from "./fleet.js";

const env: Env = {
  updateUrl: process.env.UPDATE_URL ?? "http://localhost:4001",
  witnessUrls: (process.env.WITNESS_URLS ?? "http://localhost:4101,http://localhost:4102,http://localhost:4103").split(","),
  fetch,
};
const [cmd, arg] = process.argv.slice(2);

if (cmd === "seed") console.log("published", (await seed(env)).sha256);
else if (cmd === "reset") { await reset(env); console.log("attacks cleared"); }
else if (cmd === "attack1") { const id = arg ?? "c7"; await attack1(env, id); console.log(`update server now serves ${id} a tampered binary`); }
else if (cmd === "fleet") {
  const res = await runFleet(env, Number(arg ?? 12));
  for (const r of res) console.log(r.id.padEnd(4), r.state === "verified" ? "verified" : `BLOCKED ${r.reason}`);
  const alerts = await Promise.all(env.witnessUrls.map((w) => fetch(`${w}/alerts`).then((r) => r.json() as Promise<unknown[]>).catch(() => null)));
  console.log("witness alerts:", alerts.map((a, i) => `w${i + 1}=${a ? a.length : "down"}`).join(" "));
} else console.log(`usage: seed | fleet [n] | attack1 [clientId, default c7] | reset  (ids: ${clientIds(3).join(",")}…)`);
