// The cache-doctor demo page on Cloudflare Workers.
//   GET /               the page
//   GET /api/check?url= the diagnosis as JSON
// Only the diagnosis leaves this Worker, never the fetched page, so it is not a proxy.

import { check } from "../src/probe.ts";
import { APP_JS, PAGE, STYLE_CSS } from "./page.ts";

interface Env {
  LIMITER?: { limit(opts: { key: string }): Promise<{ success: boolean }> };
}

const BLOCKED_SUFFIXES = [".localhost", ".local", ".internal", ".lan", ".home.arpa", ".onion", ".test", ".invalid", ".example"];

export function refuse(url: URL, ownHost: string): string | null {
  if (url.protocol !== "https:" && url.protocol !== "http:") return "only http and https URLs";
  if (url.username || url.password) return "no credentials in the URL";
  if (url.port && url.port !== "80" && url.port !== "443") return "only the standard ports 80 and 443";
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (host.startsWith("[") || host.includes(":") || /^[\d.]+$/.test(host) || /^0x/i.test(host)) return "use a host name, not an IP address";
  if (!host.includes(".") || host === "localhost" || BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) return "not a public host name";
  if (host === ownHost.toLowerCase()) return "that is this page";
  return null;
}

const SECURITY = {
  "content-security-policy":
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...SECURITY, ...extra },
  });
}

function asset(body: string, type: string): Response {
  // This page passes its own check: public, shared for 5 minutes, revalidated after.
  return new Response(body, {
    headers: { "content-type": type, "cache-control": "public, max-age=300, s-maxage=3600, stale-while-revalidate=600", ...SECURITY },
  });
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const here = new URL(req.url);
    if (req.method !== "GET" && req.method !== "HEAD") return json({ error: "use GET" }, 405, { allow: "GET, HEAD" });
    if (here.pathname === "/") return asset(PAGE, "text/html; charset=utf-8");
    if (here.pathname === "/app.js") return asset(APP_JS, "text/javascript; charset=utf-8");
    if (here.pathname === "/style.css") return asset(STYLE_CSS, "text/css; charset=utf-8");
    if (here.pathname !== "/api/check") return json({ error: "not found" }, 404);

    const raw = (here.searchParams.get("url") ?? "").trim();
    let target: URL;
    try {
      target = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`);
    } catch {
      return json({ error: "That is not a URL." }, 400);
    }
    const why = refuse(target, here.hostname);
    if (why) return json({ error: `Refused: ${why}.` }, 400);

    // Same URL within a minute: answer from the edge cache, no new fetches.
    const cache = caches.default;
    const key = new Request(`${here.origin}/api/check?url=${encodeURIComponent(target.toString())}`);
    const cached = await cache.match(key);
    if (cached) return cached;

    if (env.LIMITER) {
      const ip = req.headers.get("cf-connecting-ip") ?? "unknown";
      const { success } = await env.LIMITER.limit({ key: ip });
      if (!success) return json({ error: "Too many checks from your address. Try again in a minute." }, 429, { "retry-after": "60" });
    }

    try {
      const report = await check(target.toString(), {
        timeoutMs: 8000,
        maxBytes: 200 * 1024,
        insideCloudflare: true,
        allow: (u) => {
          const r = refuse(u, here.hostname);
          if (r) throw new Error(`a redirect went somewhere refused (${r})`);
        },
      });
      const res = json(report, 200, { "cache-control": "public, max-age=0, s-maxage=60" });
      ctx.waitUntil(cache.put(key, res.clone()));
      return res;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return json({ error: `Could not check ${target.host}: ${msg.slice(0, 200)}` }, 502);
    }
  },
} satisfies ExportedHandler<Env>;
