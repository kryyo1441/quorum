// The adversarial suite of SPEC §10. ONE module: Vitest asserts on it and the dashboard's /attack renders it, so they cannot disagree.
// Each scenario runs on its own fresh in-process world (real services, real crypto). NOT yet reviewed by Codex (SPEC says Codex owns this suite).
import { cosign, leafHashOfEntry, verifyEntry } from "@uw/log-core";
import { checkUpdate, verdictOf, type VerifyConfig, type Verdict } from "@uw/client-sdk";
import type { ReleaseEntry, STH } from "@uw/shared";
import { APP, EVIL, GOOD, PLATFORM, attackWith, clientIds, makeEntry, publish, runClient, runFleet, sha256, type ClientResult } from "./fleet.js";
import { createWorld, type World } from "./world.js";

export type ScenarioResult = {
  n: number; name: string; attack: string; expected: string; actual: string; pass: boolean;
  evidence: string[];       // what was observed, one line each
  ms: number;               // wall time of the scenario
  alertMs?: number;         // time from the attack to the first alert / block (§15)
  naive?: string;           // what a signature-only updater (hash + vendor signature, no log, no witnesses) does with the SAME attack input
};
type Run = (w: World) => Promise<{ actual: string; pass: boolean; evidence: string[]; alertMs?: number; naive?: string }>;
const EVIL2 = new TextEncoder().encode("notepad-minus 2.1.0 TAMPERED build (variant 2)");
const V200 = new TextEncoder().encode("notepad-minus 2.0.0 vulnerable build");
const kinds = async (w: World, q = "") => Promise.all(w.witnesses.map(async (x) => ((await (await w.fetch(`${x.url}/alerts${q}`)).json()) as { kind: string }[]).map((a) => a.kind)));

/** What a client at `installed` concludes about (binary, manifest), talking to `cfg`'s log and the world's witnesses. */
async function verdictFor(w: World, binary: Uint8Array, manifest: ReleaseEntry, o: { logUrl?: string; installed?: string; threshold?: number; expected?: boolean } = {}) {
  const cfg: VerifyConfig = { ...w.env.verify, logUrl: o.logUrl ?? w.env.verify.logUrl, threshold: o.threshold ?? w.env.verify.threshold,
    expected: o.expected === false ? undefined : { app: APP, platform: PLATFORM, installedVersion: o.installed ?? "2.0.0" } };
  const { checks, sth } = await checkUpdate(binary, manifest, cfg, { fetch: w.fetch, now: w.env.now! });
  return { checks, verdict: verdictOf(checks, manifest, sth) as Verdict };
}
/** The baseline Quorum replaces: today's typical updater checks the file hash against the manifest and the vendor's signature on it. Nothing else. */
function naive(w: World, binary: Uint8Array, m: ReleaseEntry): string {
  const key = w.env.verify.vendorPublicKeys[m.vendorKeyId];
  if (sha256(binary) !== m.sha256) return "blocks it locally (hash mismatch), but nobody else is told";
  if (!key || !verifyEntry(m, key)) return "blocks it (bad signature)";
  return "INSTALLS THE ATTACKER'S FILE";
}
const why = (v: Verdict) => (v.ok ? "ACCEPTED" : `${v.reason} (${v.detail})`);
const reasonOf = (v: Verdict) => (v.ok ? "ACCEPTED" : v.reason);
const post = (w: World, url: string, body: unknown) => w.fetch(url, { method: "POST", body: JSON.stringify(body) });

export const SCENARIOS: { n: number; name: string; attack: string; expected: string; run: Run }[] = [
  { n: 1, name: "Targeted binary swap", attack: "Update server serves client c7 a different binary under the same manifest", expected: "HASH_MISMATCH",
    run: async (w) => {
      await publish(w.env);
      const t0 = performance.now();
      await attackWith(w.env, "c7", EVIL);
      const res = await runFleet(w.env, 12);
      const c7 = res.find((r) => r.id === "c7")!, others = res.filter((r) => r.id !== "c7");
      const alerts = await kinds(w), alertMs = performance.now() - t0;
      const pass = c7.reason === "HASH_MISMATCH" && others.every((r) => r.state === "verified") && alerts.every((a) => a.includes("HASH_MISMATCH"));
      return { actual: c7.reason ?? "ACCEPTED", pass, alertMs, naive: naive(w, EVIL, makeEntry(w.env, GOOD)), evidence: [`c7: ${c7.reason}`, `other 11 clients verified: ${others.filter((r) => r.state === "verified").length}`, `witness alerts: ${alerts.map((a) => a.join("+")).join(" | ")}`] };
    } },
  { n: 2, name: "Forged manifest", attack: "Update server serves a binary with a manifest the vendor never signed", expected: "BAD_VENDOR_SIG or NOT_IN_LOG",
    run: async (w) => {
      const good = await publish(w.env);
      const forgedByAttacker = makeEntry({ ...w.env, vendor: { keyId: "demo", secretKey: generateAttackerKey() } }, EVIL);  // signed with the attacker's own key, claiming the vendor key id
      const edited = { ...good, sha256: sha256(EVIL) };                                                                      // genuine manifest with the hash swapped
      const a = await verdictFor(w, EVIL, forgedByAttacker), b = await verdictFor(w, EVIL, edited);
      const okSet = (v: Verdict) => !v.ok && (v.reason === "BAD_VENDOR_SIG" || v.reason === "NOT_IN_LOG");
      return { naive: naive(w, EVIL, forgedByAttacker), actual: `${reasonOf(a.verdict)} / ${reasonOf(b.verdict)}`, pass: okSet(a.verdict) && okSet(b.verdict), evidence: [`attacker-signed: ${why(a.verdict)}`, `hash swapped in genuine manifest: ${why(b.verdict)}`] };
    } },
  { n: 3, name: "Stolen key, release not logged", attack: "Attacker holds the vendor key, signs a malicious release, never logs it", expected: "NOT_IN_LOG",
    run: async (w) => {
      await publish(w.env);
      const evilEntry = makeEntry(w.env, EVIL, "2.2.0"); // validly vendor-signed, hash matches
      const { checks, verdict } = await verdictFor(w, EVIL, evilEntry);
      return { naive: naive(w, EVIL, evilEntry), actual: reasonOf(verdict), pass: !verdict.ok && verdict.reason === "NOT_IN_LOG", evidence: [`vendorSig check: ${checks.find((c) => c.id === "vendorSig")!.status} (the key IS valid)`, `verdict: ${why(verdict)}`] };
    } },
  { n: 4, name: "Stolen release key", attack: "Attacker holds the vendor's release key and tries to log a malicious release. Then the worse case: the approver key too",
    expected: "Release key alone: refused by the log (403), clients reject it. Both keys: accepted, monitor raises UNAPPROVED_RELEASE",
    run: async (w) => {
      await publish(w.env);
      const size0 = ((await (await w.fetch(`${w.env.logUrl}/sth`)).json()) as STH).treeSize;
      const upload = (e: ReleaseEntry) => w.fetch(`${w.env.updateUrl}/admin/release`, { method: "POST", body: JSON.stringify({ entry: e, binary: Buffer.from(EVIL).toString("base64") }) });
      // (a) the release key alone: no second signature
      const alone = makeEntry(w.env, EVIL, "2.2.0", { approve: false }), t0 = performance.now();
      await upload(alone);
      const refused = await post(w, `${w.env.logUrl}/entries`, alone);
      const sizeAfter = ((await (await w.fetch(`${w.env.logUrl}/sth`)).json()) as STH).treeSize;
      const blocked = await runClient(w.env, "c1");                      // the update server hands c1 the unlogged, single-signed release
      const alertMs = performance.now() - t0;
      await w.fetch(`${w.env.updateUrl}/admin/release/${APP}/2.2.0/${PLATFORM}`, { method: "DELETE" });
      // (b) both keys stolen: the log cannot tell it from the vendor, so it is accepted and only the monitor can object
      const both = makeEntry(w.env, EVIL, "2.2.0");
      await upload(both);
      const r = await post(w, `${w.env.logUrl}/entries`, both);
      await w.settle(1);                                                  // exactly ONE cycle: each witness polls and cosigns, the monitor polls once
      const alerts = w.monitor.alerts.filter((a) => a.kind === "UNAPPROVED_RELEASE" && a.version === "2.2.0");
      const accepted = await runClient(w.env, "c2");
      const tryApprove = await w.fetch(`${w.env.monitor!.url}/approved`, { method: "POST", body: JSON.stringify({ app: APP, version: "2.2.0", platform: PLATFORM, sha256: sha256(EVIL) }) }); // neither stolen key is the approval token
      const pass = refused.status === 403 && sizeAfter === size0 && blocked.state === "blocked" && blocked.reason === "BAD_VENDOR_SIG"
        && r.status === 201 && accepted.state === "verified" && alerts.length === 1 && tryApprove.status === 401;
      return { naive: naive(w, EVIL, alone) + " and nothing ever alerts the vendor", alertMs, pass,
        actual: `release key alone: log HTTP ${refused.status}, client ${blocked.reason ?? "ACCEPTED"}; both keys: ${accepted.state === "verified" ? "ACCEPTED" : accepted.reason}, monitor: ${alerts.length ? "UNAPPROVED_RELEASE" : "no alert"}`,
        evidence: [`(a) log answered HTTP ${refused.status} to the release-key-only entry; tree size stayed ${size0} -> ${sizeAfter}`, `(a) client c1 was handed it anyway: ${blocked.state} ${blocked.reason ?? ""} ${blocked.detail ?? ""}`,
          "(b) limit: with BOTH keys stolen the release is detected, NOT prevented: a client that installs before the monitor polls is exposed for one poll window", `(b) client c2: ${accepted.state}; monitor alerts: ${alerts.map((a) => `${a.kind} ${a.version}`).join(", ") || "none"}`, `(b) attacker approving its own release without the monitor token: HTTP ${tryApprove.status}`] };
    } },
  { n: 5, name: "Split view (forked log)", attack: "Log operator shows client c3 a forked tree containing a release the public log never has", expected: "Victim blocked INSUFFICIENT_COSIGS; witnesses raise INCONSISTENT_STH",
    run: async (w) => {
      await publish(w.env);
      const before = await runClient(w.env, "c1");           // before the fork is shown to witnesses everything is fine
      const fork = w.forkLog();
      const evilEntry = makeEntry(w.env, EVIL);              // attacker holds BOTH the log key and the vendor key
      await post(w, `${fork.url}/entries`, evilEntry);
      const head = (await (await w.fetch(`${fork.url}/sth`)).json()) as STH;
      const t0 = performance.now(); // the operator NEVER shows the fork to a witness; the victim client's own check forwards the head it was shown
      const { verdict, checks } = await verdictFor(w, EVIL, evilEntry, { logUrl: fork.url });
      const alertMs = performance.now() - t0, alerts = await kinds(w);
      const after = await runClient(w.env, "c1");
      // Two log-signed heads for one size prove the log equivocated, so EVERY client fails closed (SPLIT_VIEW) until the operator is dealt with.
      const pass = !verdict.ok && verdict.reason === "INSUFFICIENT_COSIGS" && alerts.every((a) => a.includes("INCONSISTENT_STH")) && before.state === "verified" && after.reason === "SPLIT_VIEW";
      return { naive: naive(w, EVIL, evilEntry) + "; a forked log is invisible to it", actual: `client: ${reasonOf(verdict)}; witnesses: ${[...new Set(alerts.flat())].join(",")}`, pass, alertMs,
        evidence: [`fork head has ${head.cosigs.length} cosigs; copying the real head's cosigs does not work (they bind the root)`, `inclusion + log signature on the fork pass: ${checks.filter((c) => ["inclusion", "logSig"].includes(c.id)).map((c) => c.status).join("/")}`, `client c3: ${why(verdict)}`, `witness alerts: ${alerts.map((a) => a.join("+")).join(" | ")}`, `honest client c1 before the fork was shown to witnesses: ${before.state}; after: ${after.state} ${after.reason ?? ""} (a proven fork blocks everyone: the log can no longer be trusted)`,
          "the victim's verification forwarded the forked head it was shown to every witness: one client's view became evidence for all"] };
    } },
  { n: 6, name: "Downgrade / replay", attack: "Old, validly signed and logged release replayed to a client that is already newer", expected: "STALE_STH (version-monotonic check)",
    run: async (w) => {
      const old = await publish(w.env, V200, "2.0.0");
      await publish(w.env, GOOD, "2.1.0");
      const a = await verdictFor(w, V200, old, { installed: "2.1.0" });
      const b = await verdictFor(w, V200, old, { expected: false });
      return { naive: naive(w, V200, old) + " (a downgrade to the vulnerable version)", actual: reasonOf(a.verdict), pass: !a.verdict.ok && a.verdict.reason === "STALE_STH", evidence: [`installed 2.1.0, offered 2.0.0: ${why(a.verdict)}`, `without \`expected\` configured the target check is skipped and the same replay is ${b.verdict.ok ? "ACCEPTED" : "blocked"}: every caller must pass \`expected\``] };
    } },
  { n: 7, name: "One witness compromised", attack: "A single witness cosigns anything, including a forked head", expected: "Still blocked (k=2 of 3)",
    run: async (w) => {
      await publish(w.env);
      const fork = w.forkLog(), evilEntry = makeEntry(w.env, EVIL);
      await post(w, `${fork.url}/entries`, evilEntry);
      const head = (await (await w.fetch(`${fork.url}/sth`)).json()) as STH;
      const bad = w.witnesses[2];
      const attach = await post(w, `${fork.url}/sth/${head.treeSize}/cosigs`, cosign(head, bad.id, bad.secretKey, new Date(w.env.now!()).toISOString())); // w3's key signs the fork
      const forkHead = (await (await w.fetch(`${fork.url}/sth`)).json()) as STH;
      const k2 = await verdictFor(w, EVIL, evilEntry, { logUrl: fork.url });
      const k1 = await verdictFor(w, EVIL, evilEntry, { logUrl: fork.url, threshold: 1 });
      // The attack only counts if the forged cosig really is on the head and valid; otherwise "blocked" would prove nothing.
      const cosigs = (c: { checks: { id: string; status: string }[] }) => c.checks.find((x) => x.id === "cosigs")!.status;
      const one = attach.status === 201 && forkHead.cosigs.length === 1;
      return { naive: naive(w, EVIL, evilEntry) + " (witnesses do not exist)", actual: reasonOf(k2.verdict), pass: one && !k2.verdict.ok && k2.verdict.reason === "INSUFFICIENT_COSIGS" && cosigs(k2) === "fail" && cosigs(k1) === "pass",
        evidence: [`forged cosig from ${bad.id} attached to the fork head: HTTP ${attach.status}, ${forkHead.cosigs.length} cosig on the head`, `k=2: ${why(k2.verdict)}`, `control, k=1: the cosignature check ${cosigs(k1).toUpperCase()}S: with k=1 one bad witness WOULD be enough (only the split-view alert raised by this very check would then stop it)`] };
    } },
  { n: 8, name: "Log or witnesses unreachable", attack: "The log, one witness, or all witnesses are down; or witnesses stop cosigning", expected: "Fails closed with a clear reason",
    run: async (w) => {
      const rel = await publish(w.env);
      const ev: string[] = [], bad: string[] = [];
      const t = async (label: string, setup: () => void, undo: () => void) => { setup(); const { verdict } = await verdictFor(w, GOOD, rel); undo(); ev.push(`${label}: ${why(verdict)}`); if (verdict.ok || !verdict.detail) bad.push(label); return reasonOf(verdict); };
      const r1 = await t("log down", () => w.down.add("log"), () => w.down.delete("log"));
      const r2 = await t("one witness down", () => w.down.add("w1"), () => w.down.delete("w1"));
      const r3 = await t("all witnesses down", () => w.witnesses.forEach((x) => w.down.add(x.host)), () => w.down.clear());
      const r4 = await t("witnesses silent for 10 min", () => { w.clock.t += 10 * 60_000; }, () => {});
      return { actual: [r1, r2, r3, r4].join(" / "), pass: bad.length === 0, evidence: ev };
    } },
  { n: 9, name: "Stored log leaf tampered", attack: "Attacker with database access rewrites a stored leaf", expected: "Proofs fail; witnesses alert",
    run: async (w) => {
      const rel = await publish(w.env);
      await publish(w.env, V200, "2.0.0"); await publish(w.env, V200, "2.0.1"); // 3 leaves: a witness's consistency proof from size 3 covers leaves 0-1
      const leaf = (await w.store.all())[0];
      // (a) edit only the entry: the log re-derives every leaf hash on read and refuses to serve
      const keepEntry = leaf.entry;
      leaf.entry = { ...leaf.entry, sha256: sha256(EVIL) };
      const a = await verdictFor(w, GOOD, rel), aStatus = (await w.fetch(`${w.env.logUrl}/entries`)).status;
      leaf.entry = keepEntry;
      // (b) edit entry AND leaf hash (the attacker also fixes the stored hash): the log serves it, but proofs no longer reach the signed root
      const keepHash = leaf.leafHash, tampered = { ...rel, sha256: sha256(EVIL) };
      leaf.entry = tampered; leaf.leafHash = leafHashOfEntry(tampered);
      const t0 = performance.now();
      await publish(w.env, GOOD, "2.1.2", 300).catch(() => {}); // expected to time out: no witness cosigns a head whose consistency proof fails   // the log keeps appending; witnesses now ask it for a consistency proof
      await w.settle(2);
      const alertMs = performance.now() - t0, alerts = await kinds(w);
      const b = await verdictFor(w, GOOD, rel);
      leaf.entry = keepEntry; leaf.leafHash = keepHash;
      const pass = !a.verdict.ok && aStatus === 500 && !b.verdict.ok && alerts.every((x) => x.includes("INCONSISTENT_STH")) && w.monitor.alerts.some((x) => x.kind === "INCONSISTENT_STH");
      return { actual: `${reasonOf(a.verdict)} / ${reasonOf(b.verdict)}; witnesses: ${alerts.map((x) => x.join("+") || "none").join(" | ")}`, pass, alertMs,
        evidence: [`(a) entry edited: log answers HTTP ${aStatus}; client: ${why(a.verdict)}`, `(b) entry and leaf hash edited: client: ${why(b.verdict)}`, `(b) witness consistency check (size 3 to 4) vs. their last cosigned head: ${alerts.map((x) => x.join("+") || "none").join(" | ")}`, `(b) monitor, which remembers every leaf hash it saw: ${w.monitor.alerts.filter((x) => x.kind === "INCONSISTENT_STH").length} rewrite alert(s)`, "limit: whether a witness's consistency proof touches the tampered leaf depends on tree shape; the monitor's first-seen leaf hashes catch it regardless"] };
    } },
  { n: 10, name: "Different hashes for one version", attack: "Two clients are told different hashes (two tampered binaries) for the same version", expected: "HASH_MISMATCH",
    run: async (w) => {
      await publish(w.env);
      const t0 = performance.now();
      await attackWith(w.env, "c1", EVIL); await attackWith(w.env, "c2", EVIL2);
      const res = await runFleet(w.env, 12), alertMs = performance.now() - t0, alerts = await kinds(w);
      const blocked = res.filter((r) => r.state === "blocked");
      const pass = blocked.map((r) => r.id).sort().join() === "c1,c2" && blocked.every((r) => r.reason === "HASH_MISMATCH") && alerts.every((a) => a.filter((k) => k === "HASH_MISMATCH").length >= 2);
      return { actual: `blocked ${blocked.map((r) => r.id).join(",")}: ${[...new Set(blocked.map((r) => r.reason))].join(",")}`, pass, alertMs, evidence: [`witness alerts: ${alerts.map((a) => a.join("+")).join(" | ")}`, `other ${res.length - blocked.length} clients verified`] };
    } },
];

import { generateKeypair } from "@uw/log-core";
const generateAttackerKey = () => generateKeypair().secretKey;

export async function runScenario(n: number): Promise<ScenarioResult> {
  const s = SCENARIOS.find((x) => x.n === n);
  if (!s) throw new Error(`no scenario ${n}`);
  const t0 = performance.now(), w = createWorld();
  try { const r = await s.run(w); return { n, name: s.name, attack: s.attack, expected: s.expected, ...r, ms: performance.now() - t0 }; }
  catch (e) { return { n, name: s.name, attack: s.attack, expected: s.expected, actual: "ERROR", pass: false, evidence: [e instanceof Error ? e.stack ?? e.message : String(e)], ms: performance.now() - t0 }; }
}

/** §15 numbers for one fleet run on a fresh world. In-process: network time is function-call time, so real latency is higher (use `pnpm fleet` against a live stack for that). */
export async function metrics() {
  const w = createWorld();
  const e = w.env, t0 = performance.now();
  await publish(e);
  const publishMs = performance.now() - t0;
  const res: ClientResult[] = await runFleet(e, 12);
  const q = (xs: number[], p: number) => [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor(p * xs.length))];
  const ms = res.map((r) => r.ms);
  const N = 200, w2 = createWorld(), a0 = performance.now();
  for (let i = 0; i < N; i++) await w2.fetch("http://log/entries", { method: "POST", body: JSON.stringify(makeEntry(w2.env, GOOD, `3.0.${i}`)) });
  return {
    note: "in-process: no real network, memory store, one machine",
    verifyMs: { p50: q(ms, 0.5), p95: q(ms, 0.95), max: Math.max(...ms) },
    hashMs: res[0].hashMs, networkAndCryptoMs: res[0].networkMs,
    overheadBytes: res[0].bytes, publishToCosignedMs: publishMs,
    appendsPerSecond: (N / (performance.now() - a0)) * 1000, clients: clientIds(res.length).length,
  };
}
export async function runAll() { const results: ScenarioResult[] = []; for (const s of SCENARIOS) results.push(await runScenario(s.n)); return results; }
