"use server";
import { randomBytes } from "node:crypto";
import { revalidatePath } from "next/cache";
import { appendEntry } from "@/lib/api";

// ponytail: demo publish. Random hash and placeholder vendorSig until the vendor CLI signs a real binary.
export async function publishRelease(f: FormData) {
  const app = String(f.get("app")), version = String(f.get("version")), platform = String(f.get("platform"));
  const ok = await appendEntry({ app, version, platform: platform as "win-x64", sha256: randomBytes(32).toString("hex"), size: 0,
    url: "", publishedAt: new Date().toISOString(), vendorKeyId: "demo", vendorSig: "unsigned-demo" });
  revalidatePath("/releases");
  if (!ok) throw new Error("log-server rejected or could not be reached");
}
