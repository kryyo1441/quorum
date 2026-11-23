# Demo script (about 3 minutes)

## Before you start (once)

```bash
npx -y pnpm@10 env:init          # fresh keys in .env (skip if .env exists)
docker compose up --build        # the one-shot `seed` service publishes notepad-minus 2.1.0 and waits for 2 cosignatures
```

Open http://localhost:3000. Check: **Witnesses** shows w1, w2, w3 online, **Log** shows tree size 1 with three cosignature badges. Click **Reset everything** on `/fleet` so no attack is armed. Use a window at least 1400 px wide.

## Script

| Time | Do | Say |
|---|---|---|
| 0:00 | Overview page | "Four update channels hijacked in 18 months. Signatures did not save them: the attacker had the server, or the key. And several attacks were selective: the AOMEI tampering lasted 5 to 10 minutes. Nobody can catch a bad update that only the victim sees." |
| 0:25 | **Log**: click the leaf, watch the proof verify; **Witnesses** | "The vendor publishes to a public append-only log. Three independent witnesses check it only ever grows and cosign each head. This proof is verified in your browser, not on our server." |
| 0:50 | **Fleet** → Roll out. Click one green tile | "Twelve clients, each running eight checks before install: hash, vendor signature, right app, inclusion proof, log signature, two of three witness cosignatures, freshness, no open alert. All green." |
| 1:15 | Attack **1** with target #7, Roll out | "Now the update server is compromised and serves client 7 a different file under the same manifest. Seven goes red with `HASH_MISMATCH`. The other eleven are unaffected." Open **Witnesses**: "and every witness raised an alert, so this is no longer invisible." |
| 1:50 | **Reset everything**. Attack **5** with target #3, Roll out | "Worse: the log operator itself shows client 3 a forked tree containing a release nobody else has. Client 3 is blocked: the fork carries no witness cosignatures. And because client 3 forwarded the head it was shown, the witnesses now hold two signed heads for one tree size: proof the log lied. Everyone fails closed until that is resolved." |
| 2:25 | **Reset everything**. Attack **4**, then open **Releases** | "Last: the vendor's signing key is stolen and a malicious release is logged. Clients will accept it. But it is public now. The vendor monitor flags it as unapproved within a poll. You can steal the key. You cannot do it quietly." |
| 2:45 | **Attack** → Run all 10 | "All ten threat-model scenarios, run for real. The red line on each card is what a signature-only updater does with the same attack: in five of them it installs the attacker's file." |
| 3:00 | Done | Business slide (PITCH.md section 6) and honest limits. |

## Things that can go wrong on stage

- **Fleet shows an error**: the demo server or a service is down. `docker compose ps`; restart with `docker compose up -d`.
- **After attack 5 every tile is red on the next roll out**: expected (see script). Press **Reset everything** before the next attack.
- **Attack 4 shows no alert yet**: the monitor polls every 2 s; wait a moment, refresh **Releases**.
- **Attack 4 is permanent by design**: the log is append-only, so the malicious 2.2.0 entry stays in it after Reset, and the monitor keeps flagging it (that is the product working). Before a clean take, click the red *unapproved* badge on **Releases** to approve-and-dismiss it, or start from scratch with `docker compose down -v && docker compose up`.
- **Attack 9 (tamper a leaf in Postgres)** is on the fleet page too: use it only if you have time. It needs the Postgres-backed stack and shows up as the monitor's rewrite alert on **Witnesses**.
- Never run this with `DEV=1` in front of an audience: that mode uses public keys.

## Capture list for the video

1. Fleet all green, with one tile expanded to the eight checks.
2. Attack 1: tile 7 red, then the witnesses' alerts.
3. Attack 5: tile 3 red, `INCONSISTENT_STH` alert with its evidence drawer open.
4. Attack 4: the unapproved banner on Releases.
5. `/attack` with all ten results and the signature-only column.
6. `/verify` with a pasted hash, every row passing.
