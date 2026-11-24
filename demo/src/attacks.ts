// Attacks against the LIVE stack, for the dashboard. The demo server plays the attacker, so it is given what that attacker would hold:
// the vendor key (stolen), the log key (malicious operator), Postgres access (attacker with the database). A real deployment never gives these to one process.
import { serve } from "@hono/node-server";
import { devSecret, leafHashOfEntry, publicKeyOf } from "@uw/log-core";
import pg from "pg";
import { createApp as logApp } from "../../services/log-server/src/app.js";
import { memoryStore } from "../../services/log-server/src/store.js";
import { APP, EVIL, PLATFORM, attackWith, makeEntry, sha256, waitCosigned, witnessUrls, type Env } from "./fleet.js";

type Closable = { close: () => void };
export function liveAttacks(env: Env, o: { logSecret?: string; logId?: string; databaseUrl?: string; adminToken?: string; forkPort?: number } = {}) {
  let fork: { client: string; url: string; server: Closable } | undefined;
  let tampered: { idx: number; entry: unknown; leafHash: string } | undefined;
  const stolen = new Set<string>();
  const logSecret = o.logSecret ?? (process.env.DEV === "1" ? devSecret("log") : undefined);
  const ok = async (what: string, r: Response) => { if (!r.ok) throw new Error(`${what}: ${r.status} ${await r.text()}`); return r; };

  const closeFork = () => { fork?.server.close(); fork = undefined; };
  return {
    logFor: (id: string) => (fork?.client === id ? fork.url : undefined),
    state: () => ({ fork: fork ? { client: fork.client } : null, stolenReleases: [...stolen], tampered: tampered?.idx ?? null }),

    /** Attack 5: the log operator (holds the log key, and a stolen vendor key) shows ONE client a forked tree with a release the public log never has. */
    async fork(client: string) {
      if (!logSecret) throw new Error("LOG_SECRET_KEY is needed to play the malicious operator");
      closeFork();
      const id = { logId: o.logId ?? "uw-dev-log", secretKey: logSecret, publicKey: publicKeyOf(logSecret) };
      const app = logApp(memoryStore(), id, env.verify.vendorPublicKeys, {}, Date.now);
      const port = o.forkPort ?? 4400, server = serve({ fetch: app.fetch, port }) as unknown as Closable;
      const url = `http://127.0.0.1:${port}`, evilEntry = makeEntry(env, EVIL, "2.1.0");
      await ok("fork log", await fetch(`${url}/entries`, { method: "POST", body: JSON.stringify(evilEntry) }));
      await attackWith(env, client, EVIL, evilEntry); // the update server hands that client the evil manifest + binary
      fork = { client, url, server };
    },

    /** Attack 4: a stolen RELEASE key signs a malicious 2.2.0 and tries to log it. A release needs a second key (the approver's), so the log refuses it and every client rejects the unlogged file.
     *  With `bothKeys` the attacker also holds the approver key: the log accepts it, clients accept it, and only the monitor (its own approved list, its own token) objects. */
    async stolenKey(bothKeys = false) {
      const e = makeEntry(env, EVIL, "2.2.0", { approve: bothKeys });
      await ok("update server", await env.fetch(`${env.updateUrl}/admin/release`, { method: "POST", body: JSON.stringify({ entry: e, binary: Buffer.from(EVIL).toString("base64") }) }));
      stolen.add(e.version);
      const r = await env.fetch(`${env.logUrl}/entries`, { method: "POST", body: JSON.stringify(e) });
      if (!r.ok) return { logged: false as const, status: r.status, error: (await r.json().catch(() => ({}))) as { error?: string } };
      await waitCosigned(env, ((await r.json()) as { sth: { treeSize: number } }).sth.treeSize);
      return { logged: true as const, status: r.status };
    },

    /** Attack 9: someone with database access rewrites a stored leaf AND fixes its hash, so the log's own per-read check passes. */
    async tamper(idx = 0) {
      if (!o.databaseUrl) throw new Error("this stack uses the in-memory log: no database to tamper with (docker compose runs Postgres)");
      const db = new pg.Client({ connectionString: o.databaseUrl });
      await db.connect();
      try {
        const row = (await db.query('SELECT entry, "leafHash" FROM "Leaf" WHERE idx = $1', [idx])).rows[0];
        if (!row) throw new Error(`no leaf ${idx}`);
        if (!tampered) tampered = { idx, entry: row.entry, leafHash: row.leafHash };
        const evil = { ...row.entry, sha256: sha256(EVIL) };
        await db.query('UPDATE "Leaf" SET entry = $1, "leafHash" = $2 WHERE idx = $3', [JSON.stringify(evil), leafHashOfEntry(evil), idx]);
      } finally { await db.end(); }
    },

    /** Put everything back: update server, stolen release, fork, database row, and every witness's and the monitor's alerts. */
    async reset() {
      await env.fetch(`${env.updateUrl}/admin/reset`, { method: "POST" });
      for (const v of stolen) await env.fetch(`${env.updateUrl}/admin/release/${APP}/${v}/${PLATFORM}`, { method: "DELETE" });
      stolen.clear(); closeFork();
      if (tampered && o.databaseUrl) {
        const db = new pg.Client({ connectionString: o.databaseUrl });
        await db.connect();
        try { await db.query('UPDATE "Leaf" SET entry = $1, "leafHash" = $2 WHERE idx = $3', [JSON.stringify(tampered.entry), tampered.leafHash, tampered.idx]); } finally { await db.end(); }
        tampered = undefined;
      }
      const auth = { authorization: `Bearer ${o.adminToken ?? ""}` };
      await Promise.allSettled([...witnessUrls(env), env.monitor?.url].filter(Boolean).map((u) => env.fetch(`${u}/admin/reset`, { method: "POST", headers: auth })));
    },
  };
}
