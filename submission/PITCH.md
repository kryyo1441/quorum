# Quorum: pitch material

Slide-by-slide text. Every incident claim below was checked against the sources listed at the end; where reporting disagrees, the slide says what is solid.

## 1. Hook

**"Signatures did not save them."** Four update channels hijacked in 18 months:

| Incident | What happened (checked) | Which Quorum scenario covers it |
|---|---|---|
| **Notepad++** (June 2025, disclosed Feb 2026) | Updater traffic hijacked via the hosting provider; only a subset of users got malicious installers | #1 targeted swap, #2 forged manifest: the targeted file is not the logged file; the other users' view exposes it |
| **eScan** (20 Jan 2026) | A regional update server pushed a malicious replacement for about two hours; reports say the packages carried a valid-looking signature (eScan disputes parts of the account) | #3 / #4: a signed release that is not in the log, or is in the log and flagged |
| **AOMEI Backupper** (May to July 2026) | Update files tampered for **5 to 10 minutes at a time**; the app did not cryptographically verify them | #1, #10: a short window still leaves a different hash for the same version, which witnesses see |
| **cPGuard** (2 Nov 2026) | Fake versions 5.88.12 to 5.88.19 uploaded with a **stolen update-publishing key**; about 2,950 servers, root privileges | #4 stolen release key: refused by the log and every client (two keys). #4b both keys: cannot be done quietly, the monitor fires |

Line for the slide: *"Several were selective. Researchers reproducing the issue saw nothing."* (AOMEI: minutes-long windows. Notepad++: a subset of users.)

## 2. What we built

A client installs an update only if it is the same file everyone else was offered, and that file is in the vendor's public append-only log, cosigned by independent witnesses. The update server stops being a party you have to trust.

Diagram: vendor -> log (Merkle tree) <- 3 witnesses (consistency + cosign + gossip); client verifies 8 checks; clients report what they were offered; monitor tails the log.

## 3. Live demo (see SCRIPT.md for the words and RUNBOOK.md for the steps, 3 minutes)

## 4. Scoreboard (from `/attack`, generated, not typed)

Ten scenarios, each run against Quorum and against a **signature-only updater** (hash + vendor signature, what an unprotected updater does):

| # | Attack | Signature-only updater | Quorum |
|---|---|---|---|
| 1 | Swap one client's binary | blocks locally, nobody told | `HASH_MISMATCH`, all witnesses alert |
| 2 | Forged manifest | blocks | `BAD_VENDOR_SIG` |
| 3 | Both keys stolen, not logged | **installs** | `NOT_IN_LOG` |
| 4 | Stolen release key | **installs**, vendor never learns | log refuses (403), clients `BAD_VENDOR_SIG`; both keys stolen: accepted, monitor alerts `UNAPPROVED_RELEASE` |
| 5 | Log forks one client's view | **installs** | victim blocked, witnesses raise `INCONSISTENT_STH` |
| 6 | Downgrade | **installs** | `STALE_STH` |
| 7 | One witness compromised | **installs** | blocked at k=2 |
| 8 | Log or witnesses down | n/a | fails closed |
| 9 | Stored leaf tampered | n/a | detected |
| 10 | Two clients, two hashes | blocks locally | `HASH_MISMATCH` |

Numbers (README, in-process): about 98 ms median verification, about 850 bytes overhead per update, about 500 appends/s. Say "in-process" out loud.

## 5. Honest limits (put them on a slide; judges trust this)

- With **both** signing keys stolen, a release is **detected, not prevented**: exposure lasts one monitor poll. One key alone ships nothing.
- k witnesses colluding with the log defeats it. The demo's witnesses are all ours.
- Witnesses learn of a fork only if a client shown the fork verifies and forwards the head.
- Downgrade protection needs the app to pass `expected`.
- No key rotation or revocation yet.
- Pseudonymous observations reduce but do not remove telemetry privacy concerns.

## 6. Business (slides 14 to 16 in the deck)

**Why now (all sourced; "supports", never "guarantees compliance"):**
- **EU Cyber Resilience Act:** reporting duties for actively exploited vulnerabilities and severe incidents live since **11 Sep 2026**; main obligations, including security updates for the support period, apply from **11 Dec 2027**; maximum fines **up to EUR 15M or 2.5% of worldwide turnover** (law-firm summaries; check Regulation Arts. 14 and 71 before quoting).
- **Incidents:** four hijacked update channels in 18 months (section 1).
- **Buyers exist for adjacent products:** Chainguard reportedly grew ARR to about **$40M** (FY2025) selling software supply-chain trust, and raised $356M at a $3.5B valuation (Apr 2025). A different product, the same budget line; we do not claim to be them.

**How we make money (open protocol, paid operations):**
1. **Vendors, SaaS:** hosted log + managed witness quorum + SDK, `uw publish`, vendor monitor and alerting, audit export. Per app per month.
2. **Enterprises, fleet monitoring:** alerts when any endpoint was offered a different file than the rest, plus an evidence trail. Per endpoint per month.
3. **Regulated, self-hosted:** private log and witness federation with support and SLAs. Annual licence.
Prices are **hypotheses to validate with design partners**, not facts.

**Illustrative arithmetic (not a forecast):** at one price point of $499 per app per month: 50 apps is about $0.3M a year, 200 apps about $1.2M, 1,000 apps about $6.0M. Infrastructure is small (about 500 log appends per second measured in-process on one machine), so gross margin should be high: a hypothesis.

**Moat:** the witness network. More independent witnesses and more verifying clients make a split view harder to hide.
**Expansion:** AI agent runtimes and MCP servers (privileged local access plus vendor-controlled auto-update; the CSA note on cPGuard makes this argument).

**What we must still prove (say it out loud):** (1) vendors integrate the SDK; (2) independent witnesses join (today all three are ours); (3) someone pays. **No customers or revenue yet.**

**Risks to be ready for:** an open protocol can be self-hosted and commoditised (the answer is operations, SLAs, the independent witness network and evidence export, as with Let's Encrypt vs paid certificate vendors); cold-start for the network; long enterprise sales cycles; vendors may see an update log as exposure. No market-size numbers are claimed.

## 7. Prior art (say it, do not claim to be first)

Certificate Transparency (RFC 6962/9162), Go checksum database with witnesses, Sigstore/Rekor, TUF. Our wedge: a drop-in SDK and witness network for desktop apps and agent runtimes, plus cross-client split-view detection aimed at selective targeting.

## 8. Ask / next steps

Pilot with one vendor; recruit independent witnesses (a university, a CERT, another vendor); key rotation and revocation; interop with C2SP tlog-cosignature formats.

## Sources checked (Nov 2026)

- Notepad++: Help Net Security, 2 Feb 2026 ("How state-sponsored attackers hijacked Notepad++ updates"); Kaspersky Securelist; Dark Reading. Attribution is disputed between reports, so the slide does not name an actor.
- eScan: Help Net Security 29 Jan 2026; SecurityWeek; The Register (eScan disputes Morphisec's account).
- AOMEI: Help Net Security 20 Oct 2026; Malwarebytes Oct 2026; AOMEI advisory dated 19 Oct 2026. Start date differs between sources (April or May); the slide says "May to July".
- cPGuard: CSA research note, 7 Nov 2026 (the note says it was AI-assisted and not officially reviewed; counts are preliminary); eSecurity Planet.

- Money slide sources: European Commission and ENISA Cyber Resilience Act pages; Skadden, Goodwin and Travers Smith summaries (fines, dates); SecurityWeek, SiliconANGLE and GeekWire (Chainguard funding and ARR, reported).
