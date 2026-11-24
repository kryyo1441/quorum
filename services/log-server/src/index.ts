import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { approverKey, logIdentity, vendorKeys, witnessKeys } from "./log.js";
import { memoryStore } from "./store.js";
import { prismaStore } from "./prisma-store.js";

const id = logIdentity(), vendors = vendorKeys(), witnesses = witnessKeys(); // all throw without config unless DEV=1
if (!process.env.DATABASE_URL) console.warn("DATABASE_URL not set: using in-memory store, the log is lost on restart");
serve({ fetch: createApp(process.env.DATABASE_URL ? prismaStore(id.logId) : memoryStore(), id, vendors, witnesses, Date.now, approverKey()).fetch, port: Number(process.env.PORT ?? 4000) });
