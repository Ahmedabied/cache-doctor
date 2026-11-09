// Fetch a URL the way a CDN sees a first-time visitor: no cookies, no auth, redirects not
// followed blindly. Uses the standard fetch, so it runs the same in Node and in a Worker.

import { clean, diagnose, type Diagnosis, type Snapshot } from "./diagnose.ts";

export interface ProbeOptions {
  timeoutMs?: number;
  maxBytes?: number;
  maxRedirects?: number;
  fetch?: typeof fetch;
  // Called for every URL before it is fetched, redirects included. Throw to refuse it.
  allow?: (url: URL) => void;
}

export interface Hop {
  url: string;
  status: number;
  location: string;
}

export interface Report extends Diagnosis {
  redirects: Hop[];
  status: number;
  contentType: string;
  bytes: number;
  ms: number;
}

export const USER_AGENT = "cache-doctor/0.1 (+https://github.com/Ahmedabied/cache-doctor)";

async function readCapped(res: Response, maxBytes: number): Promise<{ text: string; bytes: number }> {
  if (!res.body) return { text: "", bytes: 0 };
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  while (bytes < maxBytes) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    bytes += value.byteLength;
  }
  await reader.cancel().catch(() => {});
  const all = new Uint8Array(Math.min(bytes, maxBytes));
  let off = 0;
  for (const c of chunks) {
    const take = Math.min(c.byteLength, all.byteLength - off);
    all.set(c.subarray(0, take), off);
    off += take;
    if (off >= all.byteLength) break;
  }
  return { text: new TextDecoder("utf-8").decode(all), bytes };
}

export async function snapshot(target: string, opts: ProbeOptions = {}): Promise<{ snap: Snapshot; hops: Hop[] }> {
  const doFetch = opts.fetch ?? fetch;
  const maxRedirects = opts.maxRedirects ?? 5;
  const hops: Hop[] = [];
  let url = new URL(target);
  for (let i = 0; ; i++) {
    opts.allow?.(url);
    const t0 = performance.now();
    const res = await doFetch(url.toString(), {
      method: "GET",
      redirect: "manual",
      headers: { "user-agent": USER_AGENT, accept: "text/html,application/xhtml+xml,*/*;q=0.8", "accept-language": "en" },
      signal: AbortSignal.timeout(opts.timeoutMs ?? 10000),
    });
    const location = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && location && i < maxRedirects) {
      hops.push({ url: url.toString(), status: res.status, location });
      await res.body?.cancel().catch(() => {});
      url = new URL(location, url);
      continue;
    }
    const { text, bytes } = await readCapped(res, opts.maxBytes ?? 512 * 1024);
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      if (k.toLowerCase() !== "set-cookie") headers[k.toLowerCase()] = v;
    });
    const setCookies = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
    return {
      snap: { url: url.toString(), status: res.status, headers, setCookies, body: text, bytes, ms: performance.now() - t0 },
      hops,
    };
  }
}

// Two anonymous requests, one after the other, then the diagnosis.
export async function check(target: string, opts: ProbeOptions = {}): Promise<Report> {
  const t0 = performance.now();
  const first = await snapshot(target, opts);
  const second = await snapshot(first.snap.url, { ...opts, maxRedirects: 0 });
  const d = diagnose(first.snap.url, first.snap, second.snap);
  if (first.hops.length) {
    d.findings.push({
      id: "redirects",
      severity: "info",
      title: `${first.hops.length} redirect${first.hops.length > 1 ? "s" : ""} before the page`,
      detail: clean(first.hops.map((h) => `${h.status} ${h.url} -> ${h.location}`).join("; ")),
      fix: "Link to the final URL. Each redirect is an extra round trip, cached or not.",
    });
  }
  return {
    ...d,
    redirects: first.hops,
    status: first.snap.status,
    contentType: first.snap.headers["content-type"] ?? "",
    bytes: first.snap.bytes,
    ms: performance.now() - t0,
  };
}
