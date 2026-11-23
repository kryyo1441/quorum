# Quorum: pitch material

Slide-by-slide text. Every incident claim below was checked against the sources listed at the end; where reporting disagrees, the slide says what is solid.

## 1. Hook

**"Signatures did not save them."** Four update channels hijacked in 18 months:

| Incident | What happened (checked) | Which Quorum scenario covers it |
|---|---|---|
| **Notepad++** (June 2025, disclosed Feb 2026) | Updater traffic hijacked via the hosting provider; only a subset of users got malicious installers | #1 targeted swap, #2 forged manifest: the targeted file is not the logged file; the other users' view exposes it |
| **eScan** (20 Jan 2026) | A regional update server pushed a malicious replacement for about two hours; reports say the packages carried a valid-looking signature (eScan disputes parts of the account) | #3 / #4: a signed release that is not in the log, or is in the log and flagged |
| **AOMEI Backupper** (May to July 2026) | Update files tampered for **5 to 10 minutes at a time**; the app did not cryptographically verify them | #1, #10: a short window still leaves a different hash for the same version, which witnesses see |
| **cPGuard** (2 Nov 2026) | Fake versions 5.88.12 to 5.88.19 uploaded with a **stolen update-publishing key**; about 2,950 servers, root privileges | #4 stolen key, release logged: cannot be done quietly, the monitor fires |

Line for the slide: *"Several were selective. Researchers reproducing the issue saw nothing."* (AOMEI: minutes-long windows. Notepad++: a subset of users.)

## 2. What we built

A client installs an update only if it is the same file everyone else was offered, and that file is in the vendor's public append-only log, cosigned by independent witnesses. The update server stops being a party you have to trust.

Diagram: vendor -> log (Merkle tree) <- 3 witnesses (consistency + cosign + gossip); client verifies 8 checks; clients report what they were offered; monitor tails the log.

## 3. Live demo (see DEMO.md, 3 minutes)

## 4. Scoreboard (from `/attack`, generated, not typed)

Ten scenarios, each run against Quorum and against a **signature-only updater** (hash + vendor signature, what an unprotected updater does):

| # | Attack | Signature-only updater | Quorum |
|---|---|---|---|
| 1 | Swap one client's binary | blocks locally, nobody told | `HASH_MISMATCH`, all witnesses alert |
| 2 | Forged manifest | blocks | `BAD_VENDOR_SIG` |
| 3 | Stolen key, not logged | **installs** | `NOT_IN_LOG` |
| 4 | Stolen key, logged | **installs**, vendor never learns | accepted, monitor alerts `UNAPPROVED_RELEASE` |
| 5 | Log forks one client's view | **installs** | victim blocked, witnesses raise `INCONSISTENT_STH` |
| 6 | Downgrade | **installs** | `STALE_STH` |
| 7 | One witness compromised | **installs** | blocked at k=2 |
| 8 | Log or witnesses down | n/a | fails closed |
| 9 | Stored leaf tampered | n/a | detected |
| 10 | Two clients, two hashes | blocks locally | `HASH_MISMATCH` |

Numbers (README, in-process): about 98 ms median verification, about 850 bytes overhead per update, about 500 appends/s. Say "in-process" out loud.

## 5. Honest limits (put them on a slide; judges trust this)

- Scenario 4 is **detected, not prevented**: exposure lasts one monitor poll.
- k witnesses colluding with the log defeats it. The demo's witnesses are all ours.
- Witnesses learn of a fork only if a client shown the fork verifies and forwards the head.
- Downgrade protection needs the app to pass `expected`.
- No key rotation or revocation yet.
- Pseudonymous observations reduce but do not remove telemetry privacy concerns.

## 6. Business

- **Who pays:** desktop software vendors and agent / MCP tool vendors (a "verifiable updates" badge for customers and auditors); enterprises monitoring update integrity across a fleet.
- **Pricing (proposed, untested):** per app per month for vendors (SDK + hosted log + witness network); per endpoint for fleet monitoring; self-hosted licence for regulated customers.
- **Moat:** the witness network. More independent witnesses and more verifying clients make a split view harder to hide.
- **Expansion:** agent runtimes and MCP servers, which combine privileged local access with vendor-controlled auto-update (the CSA research note on cPGuard makes this argument).
- No market-size numbers. We cite incidents instead.

## 7. Prior art (say it, do not claim to be first)

Certificate Transparency (RFC 6962/9162), Go checksum database with witnesses, Sigstore/Rekor, TUF. Our wedge: a drop-in SDK and witness network for desktop apps and agent runtimes, plus cross-client split-view detection aimed at selective targeting.

## 8. Ask / next steps

Pilot with one vendor; recruit independent witnesses (a university, a CERT, another vendor); key rotation and revocation; interop with C2SP tlog-cosignature formats.

## Sources checked (Nov 2026)

- Notepad++: Help Net Security, 2 Feb 2026 ("How state-sponsored attackers hijacked Notepad++ updates"); Kaspersky Securelist; Dark Reading. Attribution is disputed between reports, so the slide does not name an actor.
- eScan: Help Net Security 29 Jan 2026; SecurityWeek; The Register (eScan disputes Morphisec's account).
- AOMEI: Help Net Security 20 Oct 2026; Malwarebytes Oct 2026; AOMEI advisory dated 19 Oct 2026. Start date differs between sources (April or May); the slide says "May to July".
- cPGuard: CSA research note, 7 Nov 2026 (the note says it was AI-assisted and not officially reviewed; counts are preliminary); eSecurity Planet.
