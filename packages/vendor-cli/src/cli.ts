#!/usr/bin/env node
// uw keygen
// uw publish <file> --app notepad-minus --version 2.1.0 --platform win-x64 --url https://cdn.example/np-2.1.0.exe --key-id release-2026 --log https://log.example [--out manifest.json]
// The secret key is read from VENDOR_SECRET_KEY only: never from an argument, which would land in shell history and process listings.
import { writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { keygen, publish } from "./index.js";

const [cmd, ...rest] = process.argv.slice(2);
try {
  if (cmd === "keygen") {
    const k = keygen();
    console.log(`secret (keep offline, export as VENDOR_SECRET_KEY): ${k.secretKey}\npublic (register with the log, ship in clients):       ${k.publicKey}`);
  } else if (cmd === "publish") {
    const { values, positionals } = parseArgs({ args: rest, allowPositionals: true, options: { app: { type: "string" }, version: { type: "string" }, platform: { type: "string" }, url: { type: "string" }, "key-id": { type: "string" }, log: { type: "string" }, out: { type: "string" } } });
    const secretKey = process.env.VENDOR_SECRET_KEY, v = values;
    if (!secretKey) throw new Error("set VENDOR_SECRET_KEY");
    if (!positionals[0] || !v.app || !v.version || !v.platform || !v.url || !v["key-id"] || !v.log) throw new Error("usage: uw publish <file> --app --version --platform --url --key-id --log [--out manifest.json]");
    const p = await publish({ file: positionals[0], app: v.app, version: v.version, platform: v.platform as never, url: v.url, keyId: v["key-id"], secretKey, logUrl: v.log });
    if (v.out) writeFileSync(v.out, JSON.stringify(p.entry, null, 2));
    console.log(`published ${p.entry.app} ${p.entry.version} (${p.entry.platform}) as leaf #${p.leafIndex}, tree size ${p.treeSize}\nsha256 ${p.entry.sha256}${v.out ? `\nmanifest written to ${v.out}` : ""}`);
  } else { console.error("commands: keygen | publish"); process.exit(2); }
} catch (e) { console.error(`error: ${e instanceof Error ? e.message : e}`); process.exit(1); }
