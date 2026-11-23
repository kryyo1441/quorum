import { expect, test } from "vitest";
import { SCENARIOS, metrics, runScenario } from "./scenarios.js";

for (const s of SCENARIOS) test(`#${s.n} ${s.name} -> ${s.expected}`, async () => {
  const r = await runScenario(s.n);
  expect(r.evidence.join("\n") + "\n" + r.actual).toBeTruthy();
  expect(r.pass, `${r.actual}\n${r.evidence.join("\n")}`).toBe(true);
  if ([3, 4, 5, 6, 7].includes(s.n)) expect(r.naive, "a signature-only updater must be fooled here").toMatch(/INSTALLS/);
}, 30_000);
test("metrics are produced", async () => { const m = await metrics(); expect(m.overheadBytes).toBeGreaterThan(0); expect(m.appendsPerSecond).toBeGreaterThan(0); }, 60_000);
