# Quorum: the script

A spoken script for the 3-minute pitch with a live demo. It follows the slides in `deck/index.html` (open it, press **N** to see the short version of each beat as speaker notes).

**How to read this:** plain text is what you say. *Italics in brackets* are stage directions. `[DEMO]` marks the live parts: the exact clicks are in `RUNBOOK.md`. Read it aloud once; where a sentence feels stiff, say it your way. The beats matter more than the words.

Timing: about 3:15 spoken, plus the demo. Cut guide at the bottom.

---

## 0:00 · The question *(slides 1 and 2)*

*[Slide 1. Say nothing for two seconds. Then slide 2.]*

> Quick question. Think about the last time you clicked **"Update now."**
>
> Whatever came down to your machine: do you know it's the same file everyone else got?
>
> *(beat)*
>
> You don't. Nobody does. Today, the answer is: *because the server said so.*

## 0:25 · The problem *(slides 3 and 4)*

> That would be fine if update servers never got hijacked. They do. Four times in the last eighteen months.
>
> **Notepad++**: a text editor. Its updater traffic was hijacked through the hosting provider. Only some users got the malicious installer.
>
> **eScan**: an *antivirus*. A regional update server pushed malware for about two hours.
>
> **AOMEI Backupper**: the files were tampered with for **five to ten minutes at a time**, across eleven countries. The app didn't even verify them.
>
> And three weeks ago, **cPGuard**: fake versions, signed with a stolen publishing key, running as **root** on about **three thousand servers.**

*[Let the numbers sit.]*

> Notice the pattern. Several of these were **selective**. Most people got the real file. A few got the bad one. So when researchers tried to reproduce it, they got the clean file and saw *nothing.*
>
> A signature proves **who signed.** It says nothing about **who else got the same file.** Nobody can catch a bad update that only the victim sees.

## 1:05 · The idea *(slides 5 and 6)*

> So we asked: what if the answer to "did everyone get the same file?" wasn't a promise, but a **record**?
>
> That's **Quorum.**
>
> The vendor publishes every release into a **public log**, a Merkle tree that can only grow, the same idea that already protects TLS certificates.
>
> Then **three independent witnesses** check that the log only ever grows, and cosign what they saw. They gossip to each other, so a log can't show different people different things.
>
> And before an app installs anything, it checks that **enough witnesses vouch for exactly this file.** Eight checks. Any failure, *including a witness being unreachable*, and it **does not install.** It fails closed.
>
> The update server can still be hacked. It just isn't in the trust path any more.

## 1:40 · Live: three attacks *(switch to the dashboard)*

> Let me show you. This is twelve clients, each running those eight checks.

`[DEMO]` **Fleet → Roll out.** *(All twelve go green.)*

> All good. Now the attack from the news.

`[DEMO]` **Attack 1, target #7 → Roll out.**

> The update server hands client seven a different file. Seven is blocked: **hash mismatch.** The other eleven are unaffected. And look at the witnesses:

`[DEMO]` **Witnesses page.**

> Every witness raised an alert. The attack is no longer invisible. That's the whole trick.

`[DEMO]` **Reset. Attack 5, target #3 → Roll out.**

> Worse: the *log itself* cheats. It shows client three a forked tree with a release nobody else has. Client three is blocked, because that fork has no witness cosignatures. And here's what I love: client three **forwards the head it was shown** to the witnesses. Now they hold two signed heads for the same tree size. That's *proof the log lied.* One victim's view just became evidence for everyone, so everyone fails closed.

`[DEMO]` **Reset. Attack 4 → Releases page.**

> And the cPGuard case: the vendor's key is stolen, and a malicious release is logged. I'll be straight with you, clients *accept* it. It's signed, it's logged. We detect it; we don't prevent it. But it's public the instant it's logged, and the vendor monitor, which has an approved list the release key can't write to, flags it within one poll.
>
> **You can steal the key. You cannot do it quietly.**

## 2:40 · The scoreboard *(slide 11, or the /attack page)*

`[DEMO]` **Attack → Run all 10.**

> That's ten attacks from our threat model, all run for real. And next to each, the red line is what a signature-only updater does with the same attack. In five of them, it **installs the attacker's file.**
>
> A hundred and twenty-five tests. Verification in about a hundred milliseconds, about a kilobyte of overhead per update. And two independent code reviews by Codex, whose findings we fixed.

*[Say "in-process" out loud when you give the milliseconds.]*

## 3:00 · Honest limits, then the ask *(slides 13 to 16)*

> We'd rather you hear the limits from us. The monitor *detects* a stolen-key release, it doesn't prevent it. If enough witnesses *and* the log collude, it fails, and today all three of our witnesses are run by us. And there's no key rotation yet.
>
> So: **who pays?** Software vendors, and especially AI-agent and MCP-tool vendors, whose tools combine privileged access with auto-update. They pay for a "verifiable updates" badge their customers and auditors can check. The moat is the witness network: more independent witnesses and more verifying clients make a split view harder to hide.
>
> What's next: recruit independent witnesses, add key rotation, and pilot with one real vendor.
>
> *(slow)* **Signatures prove who signed. A quorum proves everyone got the same thing.**
>
> Thank you.

---

## Cut guide

| If you have | Do this |
|---|---|
| **90 seconds** | Question (0:00), one incident (cPGuard) plus the "selective" point, one sentence of idea, **Attack 1 only**, last line. |
| **2 minutes** | The above plus Attack 5 and the scoreboard sentence. |
| **3 minutes** | The full script, skipping the AOMEI and eScan details if you run long. |
| **5+ minutes** | Add: slide 7 (the eight checks), `/verify` in the browser, and the Log page's in-browser proof. |

## Likely questions, and honest answers

- **"Why not just use code signing?"** Signing proves who signed, not who else got the file. If the attacker has the server or the key, the signature is exactly what they have too.
- **"Who runs the witnesses?"** Today, us (it's a demo). The design needs independent operators: universities, CERTs, other vendors. That's the next milestone, and the moat.
- **"What if the vendor's key is stolen?"** We can't prevent a malicious release, but we make it public and flag it within one poll. Key rotation and revocation are not built yet.
- **"What does this cost the user?"** About a hundred milliseconds and about a kilobyte per update, measured in-process; a real network adds round trips.
- **"Is this new?"** No: Certificate Transparency, Go's checksum database, Sigstore and TUF came first. Our angle is a drop-in SDK and witness network for desktop apps and agent runtimes, plus detecting selective targeting across clients.
- **"What if a witness is down?"** The client fails closed: it will not install while it cannot ask every witness about open alerts. That's a deliberate trade, safety over availability.
