# Quorum

A client installs an update **only if it is the same file everyone else was offered, and that file is in the vendor's public, append-only release log, cosigned by independent witnesses.** The update server stops being a party you have to trust.

Notepad++, eScan, AOMEI and cPGuard were all hit through their update channels; code signing did not save them, and some victims were the only ones who saw the bad update. Update Witness makes a targeted update impossible to keep quiet.

## How it works

1. **Publish.** The vendor signs a `ReleaseEntry` and appends it to the log (an RFC 6962 Merkle tree). The log signs a new head.
2. **Witness.** Three witnesses poll the log, verify the new head is a consistent extension of the last one they cosigned, and cosign it. They gossip heads to each other.
3. **Verify (before install).** The client checks, in order: file hash, vendor signature, target (app, platform, not a downgrade), inclusion proof, log signature, k-of-3 fresh witness cosignatures, no open alert. Any error, including an unreachable log or witness, blocks the install (fail closed).
4. **Report.** Clients report what they saw. Two different hashes for one version, or two log-signed heads for one tree size, raise an alert.
5. **Monitor.** A vendor monitor tails the log and alerts on any release that is not on the approved list.

Packages: `log-core` (Merkle tree, proofs, signatures), `witness-core` (cosign logic, fork detection, observation index, monitor), `client-sdk` (`verifyUpdate`, trust bundle, `uw-verify` CLI, browser-safe), `vendor-cli` (`uw keygen`, `uw publish`), `shared` (schemas, canonical JSON). Services: `log-server`, `witness` (x3), `monitor`, `update-server` (deliberately attackable). `apps/web` is the dashboard, `demo/` the fleet simulator, the live attacks and the adversarial suite, `examples/guarded-updater` shows how an app adopts the gate.

## Run it

```bash
npx -y pnpm@10 install
npx -y pnpm@10 -r --if-present test        # unit, integration and the 10 attack scenarios

# docker (not verified in the authoring environment: no docker daemon was available)
npx -y pnpm@10 env:init                    # fresh keys into a gitignored .env
docker compose up --build

# or without docker, in-memory log, PUBLIC dev keys (demos only), see docs/HANDOFF.md for the per-service commands
```

A one-shot `seed` container publishes `notepad-minus 2.1.0` and waits until two witnesses have cosigned it. The dashboard is on http://localhost:3000: `/fleet` (roll out, then arm attacks 1, 5, 4 or 9 against the live stack), `/attack` (all ten scenarios, with a signature-only updater alongside), `/witnesses`, `/log`, `/releases`, `/verify`. A 3-minute script is in `submission/DEMO.md`.

## Adopt it in an app

See `examples/guarded-updater`. Short version:

```bash
uw keygen                                   # vendor key; register the public half with the log
VENDOR_SECRET_KEY=... uw publish ./app.exe --app notepad-minus --version 2.1.0 --platform win-x64 --url https://cdn.example/app.exe --key-id release-2026 --log https://log.example
```

```ts
const cfg = parseTrust(trustBundle, { expected: { app, platform, installedVersion } });  // bundle baked into the app, never fetched from the log
const verdict = await verifyUpdate(bytes, manifest, cfg);                               // never throws, fails closed
if (!verdict.ok) abort(verdict.reason, verdict.detail);
```

## Prior art

- **Certificate Transparency** (RFC 6962/9162): public logs for TLS certificates. Our log format follows it.
- **Go checksum database (sum.golang.org)** with witnesses: the closest model, but only for Go modules.
- **Sigstore / Rekor**: transparency log for signatures, mostly open-source packages and containers.
- **TUF**: secure update metadata and key roles.

Our wedge is a drop-in SDK and a witness network for desktop apps and AI agent runtimes, plus cross-client split-view detection aimed at selective targeting. We do not claim to be first.

## Threat model: what the suite proves

`/attack` and `pnpm --filter @uw/demo test` run the same ten scenarios on a fresh in-process copy of the system (real services, real crypto).

| # | Attack | Outcome |
|---|---|---|
| 1 | Update server swaps one client's binary | `HASH_MISMATCH`, other 11 clients unaffected, all witnesses alert |
| 2 | Forged manifest | `BAD_VENDOR_SIG` |
| 3 | Stolen key, release not logged | `NOT_IN_LOG` |
| 4 | Stolen key, release logged | accepted; monitor raises `UNAPPROVED_RELEASE` |
| 5 | Log operator forks the tree | the victim is blocked with `INSUFFICIENT_COSIGS`, and its forwarded head makes every witness raise `INCONSISTENT_STH` |
| 6 | Downgrade replay | `STALE_STH` (only when the caller passes `expected`) |
| 7 | One witness compromised | still blocked at k=2 (with k=1 it would not be) |
| 8 | Log or witnesses down, witnesses silent | fails closed with a reason |
| 9 | Stored leaf tampered | log refuses or proofs fail; witnesses and monitor alert |
| 10 | Two clients told different hashes | `HASH_MISMATCH` |

## Honest limits

- **Scenario 4 is detected, not prevented.** A client that installs before the monitor polls is exposed for one poll window.
- Collusion of k witnesses and the log defeats the system. The demo runs one log and three witnesses we operate ourselves.
- Fork detection needs at least one client to be shown the fork and verify: that client forwards the log-signed head it saw to every witness. A fork shown to nobody who verifies, or at a size the real log has not reached, is not provable.
- A witness keeps its state in its own Postgres schema when `DATABASE_URL` is set (compose does). Without it, state is in memory and a restart is trust-on-first-use again.
- No key rotation or revocation yet: after a stolen-key alert the vendor cannot yet retire the key in-band.
- Downgrade protection needs the caller to configure `expected`; without it that check is reported as skipped.
- Once the log is proven to have equivocated, every client fails closed until the operator is dealt with. The log operator can always do that by stopping the log.
- Observations are pseudonymous and unauthenticated. That reduces but does not remove telemetry privacy concerns, and the alert scoping (docs/spec-amendments.md) exists so one bogus report cannot block a release for everyone.
- The log is single-writer, only vendor-key holders can append, and there is no rate limiting.
- `DEV=1` uses public, deterministic keys: anyone can forge. Demos only.
- The adversarial suite and witness logic have not had the independent review the spec assigns to Codex.

## Metrics (SPEC §15)

Measured by `/attack` ("Measure latency and overhead"), in-process, memory store, one machine, 12 clients:

| Metric | Value |
|---|---|
| Verification latency, median / p95 | about 98 ms / 98 ms (almost all of it the log and witness round trips; hashing a 33-byte demo file is about 0.1 ms) |
| Overhead per update (proofs, head, cosigs, alert queries) | about 850 bytes |
| Publish to cosigned | about 90 ms |
| Log appends per second | about 500 (signing and tree update, in-process; one slide only) |
| Attack to alert | scenario 4 (monitor): about 220 ms live with a 500 ms poll; per-scenario numbers on `/attack` |
| Adversarial suite | 10 of 10 as expected |

Live stack (separate processes on localhost): about 200 ms median per client, 850 bytes. Real network latency will add to both.
