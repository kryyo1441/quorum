"use server";
import { randomBytes } from "node:crypto";
import { approveEntry, devSecret, signEntry } from "@uw/log-core";
import { revalidatePath } from "next/cache";
import { appendEntry, approveRelease as approveAtMonitor, getLeaves } from "@/lib/api";

// ponytail: demo publish. The hash is random (there is no real binary), but the entry IS signed with the vendor key, as the log requires.
// Vendor key: VENDOR_SECRET_KEY (+ VENDOR_KEY_ID), or the PUBLIC dev key when DEV=1.
export async function publishRelease(f: FormData) {
  const secret = process.env.VENDOR_SECRET_KEY ?? (process.env.DEV === "1" ? devSecret("vendor") : undefined);
  const asecret = process.env.APPROVER_SECRET_KEY ?? (process.env.DEV === "1" ? devSecret("approver") : undefined);
  if (!secret || !asecret) throw new Error("no vendor or approver key: set VENDOR_SECRET_KEY and APPROVER_SECRET_KEY (or DEV=1 for the public dev keys)");
  const app = String(f.get("app")), version = String(f.get("version")), platform = String(f.get("platform"));
  const entry = approveEntry(signEntry({ app, version, platform: platform as "win-x64", sha256: randomBytes(32).toString("hex"), size: 0,
    url: "", publishedAt: new Date().toISOString(), vendorKeyId: process.env.VENDOR_KEY_ID ?? "demo" }, secret), asecret);
  const ok = await appendEntry(entry);
  if (ok) await approveAtMonitor(entry); // the vendor console is the approval authority: a release it publishes is approved
  revalidatePath("/releases");
  if (!ok) throw new Error("log-server rejected or could not be reached");
}

/** Vendor approves a release that is in the log (e.g. after reviewing an UNAPPROVED_RELEASE alert). Needs MONITOR_TOKEN, which is not the release key. */
export async function approveRelease(idx: number) {
  const l = (await getLeaves())?.find((x) => x.idx === idx);
  if (!l || !(await approveAtMonitor(l.entry))) throw new Error("could not approve: log or monitor unreachable, or MONITOR_TOKEN missing");
  revalidatePath("/releases");
}
