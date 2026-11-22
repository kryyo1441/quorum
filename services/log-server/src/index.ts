import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { stubCore } from "./core.js";
import { memoryStore } from "./store.js";
import { prismaStore } from "./prisma-store.js";

if (!process.env.DATABASE_URL) console.warn("DATABASE_URL not set: using in-memory store, the log is lost on restart");
serve({ fetch: createApp(process.env.DATABASE_URL ? prismaStore() : memoryStore(), stubCore).fetch, port: Number(process.env.PORT ?? 4000) });
