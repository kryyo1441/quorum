import { expect, test } from "vitest";
import { createWorld } from "./world.js";
import { eventBus } from "./events.js";
import { publish, runFleet, attackWith, EVIL } from "./fleet.js";

test("the bus reports releases, cosigned heads and alerts exactly once, and counts client results", async () => {
  const w = createWorld(), bus = eventBus(w.env), got: string[] = [];
  bus.subscribe((e) => got.push(e.type));
  await publish(w.env);
  await bus.start(); await new Promise((r) => setTimeout(r, 1200)); // one poll
  expect(got.filter((t) => t === "release")).toHaveLength(1);
  expect(got).toContain("cosigned");
  await attackWith(w.env, "c7", EVIL);
  for (const r of await runFleet(w.env, 12)) bus.client(r.id, r.version, r.state === "verified", r.reason);
  await new Promise((r) => setTimeout(r, 1200));
  bus.stop();
  expect(bus.stats()).toMatchObject({ clientsVerified: 11, clientsBlocked: 1 });
  expect(got.filter((t) => t === "alert").length).toBeGreaterThanOrEqual(3); // each witness raised one
  expect(got.filter((t) => t === "release")).toHaveLength(1); // not repeated
}, 20000);
