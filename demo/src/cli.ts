import { APP, PLATFORM, attack1, clientIds, reset, runFleet, seed, witnessUrls } from "./fleet.js";
import { envFromProcess } from "./env.js";

const env = envFromProcess();
const [cmd, arg] = process.argv.slice(2);

if (cmd === "seed") {
  // idempotent: `docker compose up` runs this every time
  if ((await fetch(`${env.updateUrl}/latest/${APP}/${PLATFORM}`).catch(() => undefined))?.ok) console.log("already published");
  else console.log("published and cosigned", (await seed(env)).sha256);
}
else if (cmd === "reset") { await reset(env); console.log("attacks cleared"); }
else if (cmd === "attack1") { const id = arg ?? "c7"; await attack1(env, id); console.log(`update server now serves ${id} a tampered binary`); }
else if (cmd === "fleet") {
  const res = await runFleet(env, Number(arg ?? 12));
  for (const r of res) console.log(r.id.padEnd(4), r.state === "verified" ? "verified" : `BLOCKED ${r.reason}`.padEnd(24) + (r.detail ?? ""), `${r.ms.toFixed(0)}ms ${r.bytes}B`);
  const alerts = await Promise.all(witnessUrls(env).map((w) => fetch(`${w}/alerts`).then((r) => r.json() as Promise<unknown[]>).catch(() => null)));
  console.log("witness alerts:", alerts.map((a, i) => `w${i + 1}=${a ? a.length : "down"}`).join(" "));
} else console.log(`usage: seed | fleet [n] | attack1 [clientId, default c7] | reset  (ids: ${clientIds(3).join(",")}…)`);
