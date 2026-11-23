import pg from "pg";
import type { WitnessSnapshot } from "@uw/witness-core";

/** Per-witness persistence (SPEC §12: each witness has its own schema): one row holding the witness's snapshot, in `witness_<id>.state`. */
export async function pgState(url: string, id: string) {
  const schema = `witness_${id.replace(/[^a-z0-9_]/gi, "_")}`; // id comes from config, but never interpolate it unchecked
  const db = new pg.Pool({ connectionString: url, max: 2 });
  await db.query(`CREATE SCHEMA IF NOT EXISTS "${schema}"`);
  await db.query(`CREATE TABLE IF NOT EXISTS "${schema}".state (k text PRIMARY KEY, v jsonb NOT NULL)`);
  let chain: Promise<unknown> = Promise.resolve();
  return {
    load: async (): Promise<WitnessSnapshot | undefined> => (await db.query(`SELECT v FROM "${schema}".state WHERE k = 'snapshot'`)).rows[0]?.v,
    /** Writes are queued so snapshots land in order; a failed write is reported, never swallowed silently. */
    save: (s: WitnessSnapshot) => { chain = chain.then(() => db.query(`INSERT INTO "${schema}".state (k, v) VALUES ('snapshot', $1) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v`, [JSON.stringify(s)])).catch((e) => console.error("could not persist witness state:", e.message)); return chain; },
    close: () => db.end(),
  };
}
