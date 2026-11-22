#!/usr/bin/env node
// uw-verify ./file.exe --manifest m.json --config cfg.json   (config = VerifyConfig as JSON)
import { readFileSync } from "node:fs";
import { checkUpdate, type VerifyConfig } from "./verify.js";

const [file, ...rest] = process.argv.slice(2);
const opt = (n: string) => { const i = rest.indexOf(n); return i >= 0 ? rest[i + 1] : undefined; };
const manifestPath = opt("--manifest"), configPath = opt("--config") ?? process.env.UW_CONFIG;
if (!file || !manifestPath || !configPath) { console.error("usage: uw-verify <file> --manifest <manifest.json> --config <config.json>"); process.exit(2); }

let checks;
try {
  const cfg: VerifyConfig = JSON.parse(readFileSync(configPath, "utf8"));
  ({ checks } = await checkUpdate(new Uint8Array(readFileSync(file)), JSON.parse(readFileSync(manifestPath, "utf8")), cfg));
} catch (e) { console.error(`BLOCKED: could not verify: ${e instanceof Error ? e.message : e}`); process.exit(1); }
for (const c of checks) console.log(`${c.status === "pass" ? "PASS" : c.status === "fail" ? "FAIL" : "SKIP"}  ${c.label}${c.status === "fail" ? `  [${c.reason}] ${c.detail}` : ""}`);
const ok = checks.every((c) => c.status === "pass");
console.log(ok ? "\nOK: safe to install" : "\nBLOCKED: do not install");
process.exit(ok ? 0 : 1);
