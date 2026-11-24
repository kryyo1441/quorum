# Demo runbook

How to run the Quorum demo, and what is actually happening underneath at every step. Use it two ways: as a **checklist** while you rehearse, and as a **cheat sheet** for questions ("what is that button really doing?"). The spoken words are in [`SCRIPT.md`](SCRIPT.md); the slides are in [`deck/index.html`](deck/index.html).

Everything the dashboard shows comes from the real running services, with two honest exceptions that are called out where they happen (the **Attack** page, and the in-browser **Verify** page).

---

## 1. One-time setup

You need Docker (with Compose) and Node (to run the key generator).

```bash
npx -y pnpm@10 env:init        # writes a gitignored .env with FRESH keys (refuses to overwrite)
docker compose up --build      # first run builds one image (a few minutes), then starts everything
```

**What `env:init` does.** Generates the log's signing key, the vendor's release key, the separate approver key, three witness keys, a monitor token and an admin token. Every service refuses to start without its keys, so nothing runs on shared or default secrets.

**What `docker compose up` starts.**

| Container | Port | Its job in the demo |
|---|---|---|
| `postgres` | 5432 | Stores the log's leaves and heads, and each witness's own state (schemas `witness_w1`…`w3`) |
| `log-server` | 4000 | The public append-only log. Only accepts entries signed by a registered vendor key **and** the approver key; stores witness cosignatures on each head |
| `witness-1/2/3` | 4101–4103 | Poll the log, check each new head is a consistent extension of the last, cosign it, gossip to each other, index what clients report |
| `monitor` | 4300 | Tails the log; raises `UNAPPROVED_RELEASE` for anything not on the vendor's approved list |
| `update-server` | 4001 | The vendor's normal update server, **deliberately attackable** |
| `demo` | 4200 | Plays the 12 clients and the attacker. Holds the vendor and approver keys (to publish honestly, and to play the attacker in 4 and 4b), the log key and database access. Not for exposure to the internet |
| `seed` | (exits) | One-shot: publishes `notepad-minus 2.1.0` and waits for two witness cosignatures |
| `web` | 3000 | The dashboard |

Open **http://localhost:3000**.

---

## 2. Preflight (2 minutes before you start)

| Check | How | You should see |
|---|---|---|
| All containers up, `seed` exited 0 | `docker compose ps -a` | 9 services `Up`, `seed` `Exited (0)` |
| A release is logged and cosigned | `curl -s localhost:4000/sth` | `"treeSize":1` and 3 entries under `cosigs` (w1, w2, w3) |
| Witnesses online | **Witnesses** page | w1, w2, w3 `online`, same head, `0 alerts` |
| No attack armed | **Fleet** → *Reset everything* | all tiles idle |
| Browser window | at least 1400 px wide | the fleet grid shows 6 tiles per row |

For a pristine take at any time: `docker compose down -v && docker compose up` (wipes the database).

If anything is odd, run the automated check, which exercises every attack and reset against the live stack and prints one line per assertion:

```bash
npx -y pnpm@10 --filter @uw/demo smoke
```

---

## 3. The demo, step by step

Each step has **Do**, **You see** and **Under the hood**.

### Step 0: Overview (10 s)
**Do:** open the Overview page.
**You see:** counters (releases logged, tree size, witnesses online) and a live event feed.
**Under the hood:** the counters read the log and the witnesses. The feed is a Server-Sent Events stream from the demo server, which *watches* the real services (new leaves, new heads, cosignatures, alerts) by polling them once a second, so it cannot show an event that did not happen.

### Step 1: The log and an in-browser proof (30 s)
**Do:** **Log** page. Click a leaf in the tree.
**You see:** the Merkle tree, a "root recomputed in browser matches head" badge, and three green checks for the leaf.
**Under the hood:** the browser downloads the leaf and its inclusion proof from the log, and **recomputes the leaf hash, checks the log's signature on the head, and rebuilds the path to the root, all in your browser** with the same `log-core` code the clients use. The server is only a relay. (On this page the log's public key comes from the same server for convenience; the **Verify** page pins it instead.)

### Step 2: A clean rollout (30 s)
**Do:** **Fleet** → *Roll out*. Click one green tile to expand it.
**You see:** twelve tiles go *checking → verified → installed*, each with a latency, and a pill like "850 B of proofs + head per update" (it grows slowly with the size of the log). The expanded tile lists the eight checks.
**Under the hood:** for each simulated client the demo server:
1. asks the update server for the latest manifest and downloads the file (as a client named `c1`…`c12`);
2. runs the same `checkUpdate` the SDK ships: **hash** of the file against the manifest; **vendor signature** under a known key; **target** (right app and platform, newer than the installed version); then asks the log for its head and an **inclusion proof** for this exact entry, checks the **log's signature**, counts valid **witness cosignatures** (need 2 of 3) and that they are **fresh**;
3. forwards the log-signed head it just verified to every witness (more on why in Step 4);
4. asks every witness "any open alert for this file?" (a witness that does not answer counts as a failure: fail closed);
5. reports an *observation* (what file it was offered) to the witnesses.
Results stream back one tile at a time.

### Step 3: Attack 1, one client gets a different file (45 s)
**Do:** *Reset everything*. Target **#7**, click **1 · swap one client's binary**, then *Roll out*. Open **Witnesses**.
**You see:** tile 7 red with `HASH_MISMATCH` and the hashes; the other eleven installed. On Witnesses, alerts appear on all three witnesses.
**Under the hood:** the demo server tells the update server to serve client 7 a different binary under the *same* manifest. Client 7's first check (file hash vs manifest) fails, so it never installs. It still reports its observation, so each witness now holds **two different hashes for one version**: it raises `HASH_MISMATCH`. It also looks the bad hash up in the log's entry list, which it **authenticates against the head it cosigned**, finds it absent and raises `NOT_IN_LOG`. The other eleven are unaffected because a witness only blocks a client when the log itself holds the conflicting hashes (so one bogus report cannot block a release for everyone).

### Step 4: Attack 5, the log itself cheats (60 s)
**Do:** *Reset everything*. Target **#3**, click **5 · fork the log for the target**, then *Roll out*. Open the alerts on **Witnesses**.
**You see:** tile 3 red with `INSUFFICIENT_COSIGS` (0 valid cosignatures, need 2); every other tile red with `SPLIT_VIEW`; `INCONSISTENT_STH` alerts on all witnesses with both heads as evidence.
**Under the hood:** the demo server plays a **malicious log operator** (it holds the log's signing key and a stolen vendor key). It starts a second log on port 4400, appends a different release, and shows *only client 3* that log. Client 3's checks on that fork *pass* for the inclusion proof and log signature, because the operator signed it, but the head carries **no witness cosignatures** (they cannot be copied: a cosignature signs the exact root). So client 3 is blocked. Before checking alerts, client 3 **forwards the head it was shown** to the witnesses: they now hold two log-signed heads for the same tree size with different roots, which is proof the log equivocated. They raise `INCONSISTENT_STH`, and because the log is provably untrustworthy, **every** client fails closed (`SPLIT_VIEW`) until the operator is dealt with. One victim's view became evidence for everyone.

### Step 5: Attack 4, a stolen release key (45 s)
**Do:** *Reset everything*. Click **4 · stolen release key**, then *Roll out*.
**You see:** every tile red with `BAD_VENDOR_SIG`; expand one and the "Vendor and approver signatures valid (two keys)" row is the one that failed. The live feed says the log **refused** the release (HTTP 403). The tree size on **Log** does not change.
**Under the hood:** a release needs two signatures: the vendor's **release key** and a separate **approver key**. The demo server signs a malicious `2.2.0` with the release key only (that is the key it "stole"), uploads it to the update server and tries to append it. The log checks the approver signature and answers 403, so nothing is logged. The update server still hands the file to every client, and each client rejects it at the signature check: it re-checks the approval itself, so a log that skipped the check could not get it installed either.

### Step 5b (optional): Attack 4b, both keys stolen (45 s)
**Do:** *Reset everything*. Click **4b · both keys stolen**. Open **Releases**.
**You see:** a red `UNAPPROVED_RELEASE` banner for `notepad-minus 2.2.0`, with an *unapproved* badge on its row.
**Under the hood:** now the demo server signs the malicious `2.2.0` with **both** keys, uploads it to the update server and appends it to the log. The log **accepts it**, because both signatures are valid. Witnesses cosign the new head. A client rollout now **accepts** it: with both keys stolen, the release is *detected, not prevented*. The **monitor**, polling every two seconds, authenticates the log's listing against the signed head, sees an entry that is not on its approved list and raises `UNAPPROVED_RELEASE`. The approved list needs a token *neither signing key gives you*, so the attacker cannot approve their own release. Clicking the badge approves it (that is the vendor's decision after review).
Note: the log is append-only, so this 4b entry **stays** after *Reset* (attack 4 adds nothing). Approve it to dismiss the alert, or `docker compose down -v` for a clean slate.

### Step 6: All ten scenarios (45 s)
**Do:** **Attack** → *Run all 10*.
**You see:** ten cards turn "as expected" with outcomes, timings, and a red line on most: "Signature-only updater: INSTALLS THE ATTACKER'S FILE".
**Under the hood (the honest caveat):** this page runs each scenario on a **fresh in-process copy of the whole system** (real services, real cryptography, a controllable clock) rather than on the live stack, so every run is deterministic and cannot disturb the demo. The red line is a real, simulated *signature-only* updater (checks file hash and vendor signature, nothing else) given the same attack input. The live-stack equivalents of attacks 1, 4, 5 and 9 are the buttons on the Fleet page. *Measure latency and overhead* runs a 12-client rollout in-process and reports median and p95 latency, bytes per update and log appends per second (say "in-process" when you quote them).

### Step 7 (optional): Public verifier (30 s)
**Do:** **Verify**. Paste `7e3e66525bf84bd63982dfc295b1b9929851518e53ea013b5d10a2a90c5f507c` (or any logged hash from **Releases**).
**You see:** seven green rows; the hash row says "only a hash was pasted: drop the file to check it too".
**Under the hood:** your **browser** runs the same checks directly against the log and witnesses (that is why they allow cross-origin reads), using public keys **pinned by the page** from its server configuration, never fetched from the thing being checked. Paste a hash that is not in the log and you get `NOT_IN_LOG`. Drop a file and the hash check runs too.

### Step 8 (optional): Attack 9, tamper with the database (45 s)
**Do:** *Reset everything*, click **9 · tamper a leaf in Postgres**, then *Roll out*. Watch **Witnesses**.
**You see:** all clients blocked with `BAD_INCLUSION_PROOF`; a monitor alert for the rewritten leaf.
**Under the hood:** the demo server connects to Postgres as an attacker with database access and rewrites a stored leaf **and fixes its stored hash**, so the log's own per-read check does not catch it. The log still serves the tree, but proofs no longer reach the root the log signed, so every client's inclusion check fails. The monitor remembers every leaf hash it has seen and notices one changed. *Reset* restores the original row.

---

## 4. Between takes

| You want | Do |
|---|---|
| Clear attacks and alerts | Fleet → *Reset everything* (restores the update server, removes a stolen release from it, closes the fork log, restores a tampered row, clears witness and monitor alerts) |
| A pristine system | `docker compose down -v && docker compose up` |
| Run every attack automatically | `npx -y pnpm@10 --filter @uw/demo smoke` |

## 5. If something goes wrong

| Symptom | Likely cause | Fix |
|---|---|---|
| Fleet shows an error banner | A service is down | `docker compose ps -a`; `docker compose up -d` |
| Every tile red on a plain rollout | An earlier attack 5 is still armed | *Reset everything* |
| `INSUFFICIENT_COSIGS` right after a fresh start | Witnesses have not cosigned yet | Wait 2 to 5 seconds and roll out again (`seed` waits for this, but a restart can lag) |
| Attack 4b shows no banner | The monitor polls every 2 s | Wait a moment, refresh **Releases** |
| Attack 9 says "no database to tamper with" | Running the in-memory dev stack | Use `docker compose up` (Postgres) |
| Alerts remain after *Reset* | Attack 4b's entry is permanent in the log | Approve it on **Releases**, or wipe with `down -v` |
| Page cannot reach services from another machine | `/verify` calls the log and witnesses from the *browser* at `localhost` | Open the dashboard on the same machine that runs the stack |

Never run the demo with `DEV=1` in front of an audience: that mode uses **public** keys that anyone can derive.

## 6. What to capture for the video

1. Fleet all green, one tile expanded to the eight checks.
2. Attack 1: tile 7 red, then the witnesses' alerts.
3. Attack 5: tile 3 red, then an `INCONSISTENT_STH` alert with its evidence open.
4. Attack 4: every tile red with `BAD_VENDOR_SIG` (the log refused the release). Optionally 4b: the unapproved banner on **Releases**.
5. **Attack** with all ten results and the red signature-only lines.
6. **Verify** with a pasted hash, every row passing.
