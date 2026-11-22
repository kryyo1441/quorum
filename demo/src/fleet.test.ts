import { expect, test } from "vitest";
import { createApp as updateServer } from "../../services/update-server/src/app.js";
import { createApp as witness } from "../../services/witness/src/app.js";
import { stubCore } from "../../services/witness/src/core.js";
import { devSecret } from "@uw/log-core";
import { attack1, runFleet, seed, type Env } from "./fleet.js";

// In-process wiring: route fetch by host so no ports are needed.
function env(): { e: Env; witnesses: ReturnType<typeof witness>[] } {
  const upd = updateServer();
  const witnesses = ["w1", "w2", "w3"].map((id) => witness(id, stubCore(id)));
  const f = ((url: string, init?: RequestInit) => {
    const u = new URL(url);
    const app = u.host === "update" ? upd : witnesses[Number(u.host.slice(1)) - 1];
    return Promise.resolve(app.request(u.pathname + u.search, init));
  }) as typeof fetch;
  return { e: { vendor: { keyId: "demo", secretKey: devSecret("vendor") }, updateUrl: "http://update", witnessUrls: ["http://w1", "http://w2", "http://w3"], fetch: f }, witnesses };
}

test("attack 1 + 10: only the targeted client is blocked, every witness flags the mismatch", async () => {
  const { e, witnesses } = env();
  await seed(e);
  expect((await runFleet(e)).every((r) => r.state === "verified")).toBe(true);
  expect(await (await witnesses[0].request("/alerts")).json()).toHaveLength(0);

  await attack1(e, "c7");
  const res = await runFleet(e);
  expect(res.filter((r) => r.state === "blocked").map((r) => r.id)).toEqual(["c7"]);
  expect(res.find((r) => r.id === "c7")!.reason).toBe("HASH_MISMATCH");
  for (const w of witnesses) expect(await (await w.request("/alerts")).json()).toHaveLength(1);
});
