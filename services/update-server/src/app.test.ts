import { expect, test } from "vitest";
import { createApp } from "./app.js";

const entry = { app: "a", version: "1.0.0", platform: "linux-x64", sha256: "0".repeat(64), size: 3, url: "", publishedAt: new Date().toISOString(), vendorKeyId: "k", vendorSig: "s" };
const post = (app: ReturnType<typeof createApp>, p: string, b: unknown) => app.request(p, { method: "POST", body: JSON.stringify(b) });

test("targeted client gets a different binary, others the real one", async () => {
  const app = createApp();
  await post(app, "/admin/release", { entry, binary: Buffer.from("good").toString("base64") });
  await post(app, "/admin/target", { clientId: "c7", binary: Buffer.from("evil").toString("base64") });
  const get = async (q: string) => new TextDecoder().decode(await (await app.request(`/download/a/1.0.0/linux-x64${q}`)).arrayBuffer());
  expect(await get("?client=c7")).toBe("evil");
  expect(await get("?client=c1")).toBe("good");
  expect((await (await app.request("/latest/a/linux-x64")).json()).version).toBe("1.0.0");
});
