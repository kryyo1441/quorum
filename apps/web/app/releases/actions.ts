"use server";
import { randomBytes } from "node:crypto";
import { devSecret, signEntry } from "@uw/log-core";
import { revalidatePath } from "next/cache";
import { appendEntry } from "@/lib/api";

// ponytail: demo publish. The hash is random (there is no real binary), but the entry IS signed with the vendor key, as the log requires.
// Vendor key: VENDOR_SECRET_KEY (+ VENDOR_KEY_ID), or the PUBLIC dev key when DEV=1.
export async function publishRelease(f: FormData) {
  const secret = process.env.VENDOR_SECRET_KEY ?? (process.env.DEV === "1" ? devSecret("vendor") : undefined);
  if (!secret) throw new Error("no vendor key: set VENDOR_SECRET_KEY (or DEV=1 for the public dev key)");
  const app = String(f.get("app")), version = String(f.get("version")), platform = String(f.get("platform"));
  const ok = await appendEntry(signEntry({ app, version, platform: platform as "win-x64", sha256: randomBytes(32).toString("hex"), size: 0,
    url: "", publishedAt: new Date().toISOString(), vendorKeyId: process.env.VENDOR_KEY_ID ?? "demo" }, secret));
  revalidatePath("/releases");
  if (!ok) throw new Error("log-server rejected or could not be reached");
}
