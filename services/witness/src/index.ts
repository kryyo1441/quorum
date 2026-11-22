import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { stubCore } from "./core.js";
const id = process.env.WITNESS_ID ?? "w1";
serve({ fetch: createApp(id, stubCore(id)).fetch, port: Number(process.env.PORT ?? 4101) });
