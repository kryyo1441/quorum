import { Hono } from "hono";
import type { ReleaseEntry } from "@uw/shared";

/** The vendor's normal update server. Deliberately attackable (SPEC §5, §10):
 *  `targets` maps a client id to a tampered binary, so one victim gets a different file. */
export function createApp() {
  const releases = new Map<string, { entry: ReleaseEntry; binary: Uint8Array }>(); // key: app/version/platform
  const targets = new Map<string, Uint8Array>();                                   // clientId -> evil binary
  const key = (a: string, v: string, p: string) => `${a}/${v}/${p}`;
  const app = new Hono();

  app.post("/admin/release", async (c) => {            // seed: entry + base64 binary
    const { entry, binary } = await c.req.json<{ entry: ReleaseEntry; binary: string }>();
    releases.set(key(entry.app, entry.version, entry.platform), { entry, binary: Buffer.from(binary, "base64") });
    return c.json({ ok: true });
  });
  app.post("/admin/target", async (c) => {              // attack 1: serve clientId a different binary
    const { clientId, binary } = await c.req.json<{ clientId: string; binary: string }>();
    targets.set(clientId, Buffer.from(binary, "base64"));
    return c.json({ ok: true });
  });
  app.post("/admin/reset", (c) => { targets.clear(); return c.json({ ok: true }); });

  app.get("/latest/:app/:platform", (c) => {            // newest by insertion order; ponytail: no semver sort, add if downgrade check is built
    const hit = [...releases.values()].filter((r) => r.entry.app === c.req.param("app") && r.entry.platform === c.req.param("platform")).at(-1);
    return hit ? c.json(hit.entry) : c.json({ error: "not found" }, 404);
  });
  app.get("/download/:app/:version/:platform", (c) => {
    const hit = releases.get(key(c.req.param("app"), c.req.param("version"), c.req.param("platform")));
    if (!hit) return c.json({ error: "not found" }, 404);
    const evil = targets.get(c.req.query("client") ?? "");
    return new Response(evil ?? hit.binary, { headers: { "content-type": "application/octet-stream" } });
  });
  return app;
}
