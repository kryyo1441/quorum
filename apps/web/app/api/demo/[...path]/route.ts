// Same-origin proxy to the demo server (which holds the vendor key and drives the live stack), so the browser needs no CORS and no secrets.
export const dynamic = "force-dynamic";
const DEMO = process.env.DEMO_URL ?? "http://localhost:4200";

async function proxy(req: Request, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
  try {
    const r = await fetch(`${DEMO}/${path.join("/")}${new URL(req.url).search}`, {
      method: req.method, body: req.method === "GET" ? undefined : await req.text(), headers: { "content-type": "application/json" }, cache: "no-store",
    });
    return new Response(r.body, { status: r.status, headers: { "content-type": r.headers.get("content-type") ?? "application/json", "cache-control": "no-store" } });
  } catch (e) {
    return Response.json({ error: `demo server unreachable: ${e instanceof Error ? e.message : e}` }, { status: 502 });
  }
}
export { proxy as GET, proxy as POST };
