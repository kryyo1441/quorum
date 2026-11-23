import { expect, test } from "vitest";
import { createWorld } from "../../demo/src/world.js";
import { EVIL, GOOD, attackWith, publish } from "../../demo/src/fleet.js";
import { guardedUpdate } from "./updater.js";

async function setup() {
  const w = createWorld(); await publish(w.env);
  const trust = { logUrl: w.env.logUrl, logPublicKey: w.env.verify.logPublicKey, threshold: 2, maxAgeMs: 300000, vendorPublicKeys: w.env.verify.vendorPublicKeys, witnesses: w.env.verify.witnesses };
  const installed: string[] = [];
  const go = (version = "2.0.0", client = "c1") => guardedUpdate({ updateUrl: w.env.updateUrl, trust, current: { app: "notepad-minus", platform: "win-x64", version }, install: (f) => installed.push(f), now: w.env.now, fetch: ((u: string, i?: RequestInit) => w.fetch(String(u).includes("/download/") ? `${u}?client=${client}` : String(u), i) /* the demo update server tells clients apart by this query */
    ) as typeof fetch });
  return { w, go, installed };
}
test("a genuine release installs; a swapped binary, a downgrade and a dead witness all leave the disk untouched", async () => {
  const { w, go, installed } = await setup();
  expect((await go()).ok).toBe(true);
  expect(installed).toHaveLength(1);

  const down = await go("2.1.0");                        // already on 2.1.0: offered 2.1.0 again = not newer
  expect(down).toMatchObject({ ok: false, reason: "STALE_STH" });

  w.down.add("w1");
  expect(await go()).toMatchObject({ ok: false, reason: "INSUFFICIENT_COSIGS" });
  w.down.delete("w1");

  await attackWith(w.env, "c1", EVIL);
  expect(await go()).toMatchObject({ ok: false, reason: "HASH_MISMATCH" });
  expect(installed).toHaveLength(1);                     // nothing was installed after the first success
  void GOOD;
});
