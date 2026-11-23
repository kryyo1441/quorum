# Guarded updater

How an app adopts Quorum. You keep your update server and installer; you add one gate.

```ts
const verdict = await verifyUpdate(downloadedBytes, manifest, trust);   // never throws, fails closed
if (!verdict.ok) abort(verdict.reason, verdict.detail);
install(downloadedBytes);
```

`updater.ts` is the whole pattern. Three things are yours to set up:

1. **Trust bundle** (`trust.json`, baked into the app at build time). It carries the log's public key, the witnesses' keys and URLs, the vendor's public key(s) and `threshold` (k of n). **Never fetch these from the log or witnesses you are about to check**: that would let a compromised log vouch for itself. See `trust.example.json`.
2. **`expected`**: this install's app, platform and current version. Without it the downgrade check is skipped (reported, not hidden).
3. **Publishing**: `uw publish ./app.exe --app notepad-minus --version 2.1.0 --platform win-x64 --url https://cdn.example/app.exe --key-id release-2026 --log https://log.example` (secret from `VENDOR_SECRET_KEY`).

## For an AI agent runtime or MCP server

The same gate fits any auto-updating tool that runs with local privileges: call `verifyUpdate` on the downloaded package before it is unpacked or `require`d. A runtime that loads third-party tool servers can pin one trust bundle per tool vendor, so a hijacked package registry or CDN cannot push code to one victim without the log (and the witnesses) seeing it.

## Run it against the demo stack

```bash
npx tsx updater.ts trust.json http://localhost:4001 notepad-minus win-x64 2.0.0
```
