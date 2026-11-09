// Why can this response not be shared from a cache? Pure analysis: give it two anonymous
// snapshots of the same URL (fetched one after the other) and it explains what it finds.
// No network, no Node or Worker APIs, so the CLI and the Worker share it.

export type Severity = "blocks" | "hurts" | "info";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  fix: string;
}

export interface Snapshot {
  url: string;
  status: number;
  headers: Record<string, string>; // lower-case names
  setCookies: string[];
  body: string;
  bytes: number;
  ms: number;
}

export interface Diagnosis {
  url: string;
  verdict: "refused" | "cached-unsafe" | "cached-at-cdn" | "cacheable" | "cacheable-with-issues" | "not-cacheable";
  ttl: number | null;
  cdn: { name: string; status: string[] } | null;
  findings: Finding[];
}

// Statuses a cache may store without being told how long (RFC 9110, section 15.1).
const CACHEABLE_BY_DEFAULT = new Set([200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501]);
const TRACKING = /^(utm_[a-z_]+|gclid|gbraid|wbraid|dclid|fbclid|msclkid|yclid|igshid|mc_cid|mc_eid|_ga|_gl|_hsenc|_hsmi|srsltid|ref_src)$/i;
const BUSTERS = /^(_|cb|cachebust(er)?|nocache|no_cache|t|ts|timestamp|rand|random|v)$/i;
// Cookies that CDNs and bot shields add at the edge, after the cache lookup. They are not part
// of the cached page, so they do not stop the CDN from caching it.
const EDGE_COOKIES = /^(__cf_bm|_cfuvid|cf_clearance|__cflb|__cfruid|__cfwaitingroom|ak_bmsc|bm_sv|bm_sz|bm_mi|_abck|akaalb_\w+|incap_ses_\d+_\d+|visid_incap_\d+|nlbi_\d+|ASLBSA|ASLBSACORS|sucuri_cloudproxy_uuid_[0-9a-f]+)$/i;
// Stickiness cookies from load balancers in front of the origin (AWS ALB and ELB, F5 BIG-IP, Azure App Service).
// Unlike edge cookies they do reach a CDN in front of them, so they still stop it caching. But they can be set fresh
// on every response by a balancer sitting in front of an origin cache (Varnish, nginx), so they say nothing about
// whether the page's own cookies were stored.
const LB_COOKIES = /^(AWSALB|AWSALBCORS|AWSALBTG|AWSALBTGCORS|AWSELB|BIGipServer[\w.~-]*|ARRAffinity|ARRAffinitySameSite)$/;
const STATIC_TYPES = /^(text\/css|(text|application)\/javascript|image\/|font\/|audio\/|video\/|application\/(wasm|pdf|zip|octet-stream))/;

// Everything a server sends is untrusted. Control characters and bidi overrides would let a
// page rewrite the terminal or disguise text, so they are shown as codes.
export function clean(text: string): string {
  return text.replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

export function parseCacheControl(value: string | undefined): Map<string, string | true> {
  const out = new Map<string, string | true>();
  if (!value) return out;
  for (const part of value.match(/(?:[^,"]|"[^"]*")+/g) ?? []) {
    const [rawKey, ...rest] = part.split("=");
    const key = (rawKey ?? "").trim().toLowerCase();
    if (!key) continue;
    const v = rest.join("=").trim().replace(/^"(.*)"$/, "$1");
    if (!out.has(key)) out.set(key, rest.length ? v : true);
  }
  return out;
}

// Cache-Status (RFC 9211) is a structured list: one member per cache, each with parameters, for
// example `ExampleCache; hit, OriginCache; fwd=uri-miss; stored`. Parameter values may be tokens,
// numbers, ?1 / ?0 or quoted strings (which may contain commas and semicolons).
export function parseCacheStatus(value: string): Array<{ cache: string; params: Map<string, string | boolean> }> {
  const out: Array<{ cache: string; params: Map<string, string | boolean> }> = [];
  for (const member of value.match(/(?:[^,"]|"(?:[^"\\]|\\.)*")+/g) ?? []) {
    const [name = "", ...rest] = member.match(/(?:[^;"]|"(?:[^"\\]|\\.)*")+/g) ?? [];
    const params = new Map<string, string | boolean>();
    for (const p of rest) {
      const eq = p.indexOf("=");
      const key = (eq < 0 ? p : p.slice(0, eq)).trim().toLowerCase();
      if (!key || params.has(key)) continue;
      const raw = eq < 0 ? "?1" : p.slice(eq + 1).trim();
      params.set(key, raw === "?1" ? true : raw === "?0" ? false : raw.replace(/^"(.*)"$/s, "$1"));
    }
    out.push({ cache: name.trim().replace(/^"(.*)"$/s, "$1"), params });
  }
  return out;
}

// The older one-word status headers (X-Cache, CF-Cache-Status and friends) can list several caches,
// "MISS, HIT". "HIT-FOR-PASS" (Varnish, Fastly) is a remembered decision NOT to cache: a miss.
function wordHit(value: string): boolean {
  return value.split(",").some((part) => {
    const t = part.trim().toLowerCase();
    if (/^(tcp_)?(hit[-_ ]?for[-_ ]?pass|hitpass)/.test(t)) return false;
    return /^(hit|stale|updating|revalidated|refreshhit|tcp_(mem_|refresh_|ims_|remote_)?hit)\b/.test(t);
  });
}

// After the CDNs' own headers: Bunny's CDN-Cache, the usual nginx proxy_cache headers, LiteSpeed (common on WordPress).
const STATUS_HEADERS = ["cf-cache-status", "x-vercel-cache", "cache-status", "akamai-cache-status", "x-cache",
  "cdn-cache", "x-cache-status", "x-proxy-cache", "x-litespeed-cache"];
// Varnish with no status header: X-Varnish holds this request's id, then the id of the request that stored the
// object. Two ids: it came from the cache.
const varnishIds = (h: Record<string, string>) => (h["x-varnish"] ?? "").trim().split(/\s+/).filter((x) => /^\d+$/.test(x));

// No status header at all (Google Cloud CDN sends none): Age means a cache served it, since a response carrying Age
// "was not generated or validated by the origin server for this request" (RFC 9111, 5.1). Age 0 counts only when it
// appeared on the second request after none on the first: stored by the first, served within the same second.
// An Age of 0 on both is what some origins and pass-through proxies send every time, so it says nothing.
function ageSaysStored(h: Record<string, string>, first?: Record<string, string>): boolean {
  const raw = (h["age"] ?? "").trim();
  if (!/^\d+$/.test(raw)) return false;
  return Number(raw) > 0 || (first !== undefined && first["age"] === undefined);
}

// trustAge is false inside a Worker: Cloudflare's own subrequest cache can answer and set Age itself.
export function servedFromCache(h: Record<string, string>, first?: Record<string, string>, trustAge = true): boolean {
  const name = STATUS_HEADERS.find((n) => h[n]);
  if (!name) return varnishIds(h).length === 2 || (trustAge && ageSaysStored(h, first));
  if (name === "cache-status") return parseCacheStatus(h[name]!).some((m) => m.params.get("hit") === true);
  return wordHit(h[name]!);
}

// An HTTP date in one of the three forms RFC 9110 (5.6.7) says a recipient must accept, or null.
// Anything else (Expires: 0, Expires: 2030) is not a date, which RFC 9111 (5.3) says means expired.
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const MON = MONTHS.join("|");
const IMF = new RegExp(`^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), (\\d{2}) (${MON}) (\\d{4}) (\\d{2}):(\\d{2}):(\\d{2}) GMT$`);
const RFC850 = new RegExp(`^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (\\d{2})-(${MON})-(\\d{2}) (\\d{2}):(\\d{2}):(\\d{2}) GMT$`);
const ASCTIME = new RegExp(`^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (${MON}) ([ \\d]\\d) (\\d{2}):(\\d{2}):(\\d{2}) (\\d{4})$`);

export function httpDate(value: string | undefined, now = Date.now()): number | null {
  if (value === undefined) return null;
  const v = value.trim();
  let day: number, mon: string, year: number, hh: number, mm: number, ss: number;
  let m = IMF.exec(v);
  if (m) [day, mon, year, hh, mm, ss] = [+m[1]!, m[2]!, +m[3]!, +m[4]!, +m[5]!, +m[6]!];
  else if ((m = RFC850.exec(v))) {
    // Two-digit year: more than 50 years ahead means the century before (RFC 9110, 5.6.7).
    const yy = +m[3]!;
    const thisYear = new Date(now).getUTCFullYear();
    year = Math.floor(thisYear / 100) * 100 + yy;
    if (year > thisYear + 50) year -= 100;
    [day, mon, hh, mm, ss] = [+m[1]!, m[2]!, +m[4]!, +m[5]!, +m[6]!];
  } else if ((m = ASCTIME.exec(v))) [mon, day, hh, mm, ss, year] = [m[1]!, +m[2]!.trim(), +m[3]!, +m[4]!, +m[5]!, +m[6]!];
  else return null;
  const month = MONTHS.indexOf(mon);
  if (hh > 23 || mm > 59 || ss > 60) return null;
  const t = Date.UTC(year, month, day, hh, mm, Math.min(ss, 59));
  return new Date(t).getUTCDate() === day ? t : null; // no 31 February
}

function seconds(v: string | true | undefined): number | null {
  if (v === undefined || v === true) return null;
  return /^\d+$/.test(v) ? Number(v) : null;
}

function list(value: string | undefined): string[] {
  return (value ?? "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
}

function cookieName(c: string): string {
  return (c.split(";")[0] ?? "").split("=")[0]?.trim() || "(unnamed)";
}

export interface DiagnoseOptions {
  // Set when the probe itself runs on Cloudflare (a Worker). Cloudflare's fetch path then adds
  // cf-* headers and rewrites "server" to "cloudflare" on every response, even from sites that
  // are not on Cloudflare, so none of those headers can be trusted and all of them are ignored.
  insideCloudflare?: boolean;
}

function ownCfHeaders(h: Record<string, string>, opts: DiagnoseOptions): Record<string, string> {
  if (!opts.insideCloudflare) return h;
  const rest = { ...h };
  for (const k of Object.keys(rest)) if (k.startsWith("cf-")) delete rest[k];
  if ((rest["server"] ?? "").toLowerCase() === "cloudflare") delete rest["server"];
  return rest;
}

const REFUSED = new Set([401, 403, 407, 419, 429]);

export function detectCdn(h: Record<string, string>): string | null {
  if (h["cf-cache-status"] || h["cf-ray"] || (h["server"] ?? "").toLowerCase() === "cloudflare") return "Cloudflare";
  if (h["x-vercel-cache"] || h["x-vercel-id"]) return "Vercel";
  if (h["x-amz-cf-id"] || /cloudfront/i.test(h["via"] ?? "") || /cloudfront/i.test(h["x-cache"] ?? "")) return "CloudFront";
  if (h["x-served-by"]?.includes("cache-") || h["fastly-debug-digest"] || /fastly/i.test(h["x-cache"] ?? "")) return "Fastly";
  if (h["x-nf-request-id"]) return "Netlify";
  if (h["akamai-cache-status"] || h["x-akamai-transformed"]) return "Akamai";
  if (h["x-azure-ref"]) return "Azure Front Door";
  if (h["cdn-cache"] || /bunnycdn/i.test(h["server"] ?? "")) return "Bunny";
  if (h["x-litespeed-cache"]) return "LiteSpeed";
  if (h["x-varnish"]) return "Varnish";
  // Google's front end (Cloud CDN, and the load balancer in front of Cloud Run and App Engine) adds this Via.
  if (/(^|,)\s*1\.1 google\b/i.test(h["via"] ?? "")) return "Google Cloud";
  if (STATUS_HEADERS.some((n) => h[n]) || h["age"]) return "a cache";
  return null;
}

export function cacheStatus(h: Record<string, string>): string {
  const name = STATUS_HEADERS.find((n) => h[n]);
  if (name) return h[name]!.trim();
  const ids = varnishIds(h);
  if (ids.length) return `${ids.length === 2 ? "HIT" : "MISS"} (X-Varnish ${ids.join(" ")})`;
  return h["age"] ? `age ${h["age"]}` : "";
}

const CF_STATUS: Record<string, string> = {
  DYNAMIC: "Cloudflare did not consider this cacheable at all. By default it caches static file types only, not HTML, unless a Cache Rule says otherwise.",
  BYPASS: "Cloudflare was told not to cache it: by the origin's headers (for example Set-Cookie or no-store) or by a rule.",
  MISS: "Cloudflare could cache it, but did not have it yet.",
  EXPIRED: "Cloudflare had it, but its time ran out, so it went back to the origin.",
  HIT: "Served from Cloudflare's cache.",
  STALE: "Served stale from Cloudflare's cache while the origin was unreachable.",
  UPDATING: "Served stale from Cloudflare's cache while it fetches a fresh copy.",
  REVALIDATED: "Cloudflare checked with the origin, and its stored copy was still good.",
};

interface Diff {
  a: string;
  b: string;
  context: string;
}

// Find the places where two bodies of the same page differ. Works on lines, and on tags for
// minified HTML, after trimming the common start and end, so it stays linear on big pages.
export function bodyDiffs(a: string, b: string, max = 8): Diff[] {
  const split = (s: string) => s.replace(/>\s*</g, ">\n<").split("\n");
  const la = split(a);
  const lb = split(b);
  let start = 0;
  while (start < la.length && start < lb.length && la[start] === lb[start]) start++;
  let endA = la.length - 1;
  let endB = lb.length - 1;
  while (endA >= start && endB >= start && la[endA] === lb[endB]) {
    endA--;
    endB--;
  }
  const out: Diff[] = [];
  if (start > endA && start > endB) return out;
  // Same number of changed lines: pair them up. Otherwise report the block as one change.
  const pairs: Array<[string, string]> =
    endA - start === endB - start
      ? la.slice(start, endA + 1).map((l, i) => [l, lb[start + i] ?? ""])
      : [[la.slice(start, endA + 1).join("\n"), lb.slice(start, endB + 1).join("\n")]];
  for (const [x, y] of pairs) {
    if (x === y) continue;
    let p = 0;
    while (p < x.length && p < y.length && x[p] === y[p]) p++;
    let s = 0;
    while (s < x.length - p && s < y.length - p && x[x.length - 1 - s] === y[y.length - 1 - s]) s++;
    const before = x.slice(Math.max(0, p - 60), p);
    out.push({ a: x.slice(p, x.length - s), b: y.slice(p, y.length - s), context: before });
    if (out.length >= max) break;
  }
  return out;
}

const TOKEN_HINT = /(csrf|xsrf|authenticity_token|requestverificationtoken|__requestverification|_token|anti-?forgery|form_build_id|form_key|wpnonce)/i;
const NONCE_HINT = /nonce/i;
const TIME_HINT = /(time|date|timestamp|generated|rendered|\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2})/i;
const ID_HINT = /(request[-_]?id|trace|session|uuid|visitor|client[-_]?id)/i;

export function classify(d: Diff): "token" | "nonce" | "time" | "id" | "other" {
  const around = d.context.slice(-80) + d.a.slice(0, 80);
  if (TOKEN_HINT.test(around)) return "token";
  if (NONCE_HINT.test(around)) return "nonce";
  if (ID_HINT.test(around)) return "id";
  if (TIME_HINT.test(around)) return "time";
  return "other";
}

function mask(s: string): string {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > 12 ? `${t.slice(0, 4)}...(${t.length} chars)` : t;
}

function show(context: string): string {
  return context.replace(/\s+/g, " ").trim().slice(-50);
}

export function diagnose(url: string, a: Snapshot, b?: Snapshot, opts: DiagnoseOptions = {}): Diagnosis {
  const f: Finding[] = [];
  const add = (id: string, severity: Severity, title: string, detail: string, fix: string) =>
    f.push({ id, severity, title: clean(title), detail: clean(detail), fix: clean(fix) });
  a = { ...a, headers: ownCfHeaders(a.headers, opts) };
  if (b) b = { ...b, headers: ownCfHeaders(b.headers, opts) };
  const h = a.headers;

  // Cloudflare's own errors (520 to 530): it could not reach the site, or would not (a name that
  // points at a private address gets 530). The body is Cloudflare's error page, not the site's.
  if (a.status >= 520 && a.status <= 530) {
    add("refused", "info", `No answer from the site: status ${a.status} is a Cloudflare error`,
      "Cloudflare could not get the page from the site (it is down, or the name points somewhere Cloudflare will not go). This is Cloudflare's error page, so nothing here says how the real page is cached.",
      "Check that the site is up, then try again, or run the command line tool from your own machine.");
    return { url, verdict: "refused", ttl: null, cdn: null, findings: f };
  }
  // The site would not show us the page: diagnosing the refusal would mislead.
  if (REFUSED.has(a.status) || (a.status === 503 && /challenge/i.test(h["cf-mitigated"] ?? ""))) {
    add("refused", "info", `The site refused the check with status ${a.status}`,
      "Many sites turn away requests from cloud servers or unknown clients, so this is the refusal, not the page. Nothing here says how the real page is cached.",
      "Run the command line tool from your own machine (npx github:Ahmedabied/cache-doctor <url>), or check a page you own.");
    return { url, verdict: "refused", ttl: null, cdn: null, findings: f };
  }

  // Targeted headers (RFC 9213) win over Cache-Control at CDNs that support them.
  const targetedName = ["cloudflare-cdn-cache-control", "cdn-cache-control", "surrogate-control"].find((n) => h[n]);
  const cc = parseCacheControl(h["cache-control"]);
  const shared = targetedName ? parseCacheControl(h[targetedName]) : cc;
  if (targetedName) {
    add("targeted-cache-control", "info", `${targetedName} is set`,
      `CDNs that support it use "${h[targetedName]}" instead of Cache-Control ("${h["cache-control"] ?? "none"}"). Browsers keep using Cache-Control.`,
      "Nothing to fix. This is the clean way to give the CDN and browsers different rules.");
  }

  const sMax = seconds(shared.get("s-maxage"));
  const maxAge = seconds(shared.get("max-age"));
  // A lifetime that is not a whole number of seconds (max-age=abc, a bare max-age) counts as stale
  // (RFC 9111, 4.2.1), so the response goes back to the origin every time.
  const broken = (["s-maxage", "max-age"] as const).filter((k) => shared.has(k) && seconds(shared.get(k)) === null);
  const date = httpDate(h["date"]) ?? Date.now();
  const expiresRaw = h["expires"];
  const expires = httpDate(expiresRaw);
  let ttl: number | null = broken.length ? 0 : (sMax ?? maxAge ?? null);
  if (ttl === null && expiresRaw !== undefined) ttl = expires === null ? 0 : Math.max(0, Math.round((expires - date) / 1000));
  const explicit = ttl !== null;
  const isPublic = shared.has("public");

  // 1. Status code. `public` also lets a cache store other statuses and guess a lifetime (RFC 9111, 3 and 4.2.2).
  if (!CACHEABLE_BY_DEFAULT.has(a.status) && !explicit && !isPublic) {
    add("status", "blocks", `Status ${a.status} is not cached unless it says for how long`,
      `Caches store ${[...CACHEABLE_BY_DEFAULT].join(", ")} by default. Other statuses need an explicit lifetime.`,
      a.status >= 300 && a.status < 400
        ? "For a redirect that will not change, use 301 or 308. For a temporary one, add Cache-Control: s-maxage=60."
        : "If this response is safe to share, add Cache-Control: public, s-maxage=<seconds>.");
  } else if (a.status >= 500) {
    add("error-status", "info", `Status ${a.status}`, "This is an error response, so the diagnosis is about the error page.",
      "Add stale-if-error=86400 to Cache-Control so a cache can keep serving the last good page during outages.");
  }

  // 2. Cache-Control directives that stop a shared cache.
  if (shared.has("no-store")) {
    add("no-store", "blocks", "Cache-Control: no-store",
      "No cache, shared or private, may keep a copy of this response.",
      "Keep no-store for pages with personal data. For public pages, remove it and send Cache-Control: public, max-age=0, s-maxage=300 (fresh at the CDN for 5 minutes, always checked by browsers).");
  }
  if (broken.length) {
    const k = broken[0]!;
    const v = shared.get(k);
    add("broken-lifetime", "hurts", `Cache-Control ${k}${v === true ? " has no value" : `=${v} is not a number of seconds`}`,
      "Caches are told to treat a response with a broken lifetime as already stale (RFC 9111, 4.2.1), so every request goes back to the origin.",
      `Use whole seconds, for example ${k}=300.`);
  }
  const fields = (v: string | true | undefined) =>
    typeof v === "string" ? v.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean) : [];
  const priv = shared.get("private");
  if (priv === true) {
    add("private", "blocks", "Cache-Control: private",
      "Only the visitor's own browser may store this. CDNs and shared proxies must not.",
      "If every anonymous visitor gets the same page, replace private with public, s-maxage=<seconds>. If it is personal, it is right as it is.");
  } else if (typeof priv === "string") {
    add("private-fields", "info", `Cache-Control: private="${priv}"`,
      `A shared cache may store the response but must drop these headers: ${priv}. The RFC notes that many caches treat this like plain private and do not store the response at all.`,
      "Nothing to fix if that is intended. Check that your CDN supports the field list.");
  }
  const noCache = shared.get("no-cache");
  if (typeof noCache === "string") {
    add("no-cache-fields", "info", `Cache-Control: no-cache="${noCache}"`,
      `A cache may reuse the response without asking the origin, as long as it leaves out these headers: ${noCache}. The RFC notes that many caches treat this like plain no-cache and check with the origin every time.`,
      "Nothing to fix if that is intended. Check that your CDN supports the field list.");
  }
  const cookieDropped = [...fields(priv), ...fields(noCache)].includes("set-cookie");
  const validators = Boolean(h["etag"] || h["last-modified"]);
  if (noCache === true || (sMax === null && maxAge === 0) || sMax === 0) {
    const what = noCache === true ? "Cache-Control: no-cache" : "a lifetime of 0 seconds";
    add("revalidate-always", "hurts", `Every request goes back to the origin (${what})`,
      validators
        ? "A cache may store it, but must check with the origin before every use. With ETag or Last-Modified that check can be a quick 304, but it is still a round trip to the origin."
        : "A cache must check with the origin before every use, and without ETag or Last-Modified that check downloads the whole response again.",
      "Give the CDN a short lifetime even if browsers get none: Cache-Control: max-age=0, s-maxage=60, stale-while-revalidate=300.");
  }

  // 3. Expires and Pragma.
  if (expiresRaw !== undefined && sMax === null && maxAge === null && !broken.length && (expires === null || expires <= date)) {
    add("expires-past", "hurts", `Expires is in the past or invalid ("${expiresRaw}")`,
      "With no max-age, an Expires date that has passed, or is not an HTTP date (like 0 or 2030), makes the response stale at once (RFC 9111, 5.3).",
      "Send Cache-Control with s-maxage instead; it overrides Expires.");
  }
  if (h["pragma"]?.toLowerCase().includes("no-cache") && !h["cache-control"]) {
    add("pragma", "info", "Pragma: no-cache without Cache-Control",
      "Pragma is from HTTP/1.0. Modern caches mostly ignore it, but some treat it like no-cache.",
      "Remove Pragma and send a Cache-Control header.");
  }

  // 4. Cookies. Edge cookies (bot shields, load balancers at the CDN) are added after the cache.
  const allNames = [...new Set(a.setCookies.map(cookieName))];
  const names = allNames.filter((n) => !EDGE_COOKIES.test(n));
  const edge = allNames.filter((n) => EDGE_COOKIES.test(n));
  const cookieTitle = `Sets ${names.length === 1 ? "a cookie" : `${names.length} cookies`} on an anonymous visit: ${names.join(", ")}`;
  if (names.length && cookieDropped) {
    add("set-cookie-dropped", "hurts", cookieTitle,
      "Cache-Control names Set-Cookie, which is the standard way to say a shared cache may store the page without the cookie (RFC 9111, 5.2.2.4 and 5.2.2.7). The RFC also notes that many caches do not support the field list and treat it as plain private or no-cache, so the page may not be cached at all.",
      "Check that your CDN supports the field list. Better: do not set the cookie on an anonymous first visit.");
  } else if (names.length) {
    add("set-cookie", "blocks", cookieTitle,
      "Shared caches do not store a response that sets a cookie (Cloudflare does not, by default): the same cookie would be handed to every visitor. A first visit with no cookies should not need one.",
      "Set session cookies only after login or on POST. Move consent or analytics cookies to JavaScript, or set them from a separate uncached request." +
        (names.some((n) => LB_COOKIES.test(n))
          ? ` ${names.filter((n) => LB_COOKIES.test(n)).join(", ")} is a load balancer's stickiness cookie: turn stickiness off for pages anyone can see, or have the CDN ignore it.`
          : ""));
  }
  if (edge.length) {
    add("edge-cookie", "info", `Edge cookie${edge.length > 1 ? "s" : ""} from the CDN: ${edge.join(", ")}`,
      "These are added by the CDN's bot or load-balancing features at the edge, after the cache lookup. They are not stored with the page.",
      "Nothing to fix for caching.");
  }

  // 5. Vary.
  const vary = list(h["vary"]);
  if (vary.includes("*")) {
    add("vary-star", "blocks", "Vary: *", "Every request counts as different, so nothing can be reused.", "Name the request headers that really change the response, or drop Vary.");
  }
  for (const v of vary) {
    if (v === "cookie" || v === "authorization") {
      add(`vary-${v}`, "hurts", `Vary: ${v}`,
        `Every distinct ${v} header is its own cache entry. Anonymous visitors without cookies can share one copy, but anyone with any cookie (analytics, consent) gets a miss.`,
        "Serve the anonymous page from a URL or path that does not vary by cookie, or strip non-session cookies at the edge before the cache key is built.");
    } else if (v === "user-agent") {
      add("vary-user-agent", "hurts", "Vary: User-Agent",
        "There are thousands of User-Agent strings, so the hit rate collapses.",
        "Use responsive HTML and CSS instead, or vary on a small header you control (for example a device class set at the edge).");
    } else if (v === "accept-language") {
      add("vary-accept-language", "hurts", "Vary: Accept-Language",
        "Browsers send many slightly different Accept-Language values, so one page splits into many entries.",
        "Put the language in the URL (/en/, /ar/) and drop the Vary.");
    }
  }

  // 6. No lifetime at all.
  const type = (h["content-type"] ?? "").toLowerCase();
  if (!explicit && !shared.has("no-store") && priv !== true && noCache !== true && a.status < 400 &&
      (CACHEABLE_BY_DEFAULT.has(a.status) || isPublic)) {
    if (STATIC_TYPES.test(type)) {
      add("no-lifetime-static", "info", "No lifetime given for a static file",
        "CDNs cache common static file types by default, with their own default lifetime. Browsers guess from Last-Modified.",
        "For files with a hash in the name, send Cache-Control: public, max-age=31536000, immutable.");
    } else {
      add("no-lifetime", "hurts", "No lifetime given (no max-age, s-maxage or Expires)",
        `A cache has to guess. Many CDNs do not cache ${type.split(";")[0] || "this content type"} at all without a lifetime; Cloudflare caches HTML only when a Cache Rule says so.`,
        "Send Cache-Control: public, max-age=0, s-maxage=300, stale-while-revalidate=60 for pages that are the same for every anonymous visitor.");
    }
  } else if (ttl !== null && ttl > 0 && ttl < 60) {
    add("short-ttl", "info", `Short shared lifetime: ${ttl} s`, "The CDN will go back to the origin at least once a minute per location.",
      "If the content can be a little stale, add stale-while-revalidate so visitors never wait for the refresh.");
  }

  // 7. Query string noise in the URL itself.
  try {
    const params = [...new URL(url).searchParams.keys()];
    const tracking = params.filter((p) => TRACKING.test(p));
    const busters = params.filter((p) => BUSTERS.test(p));
    if (tracking.length) {
      add("tracking-params", "hurts", `Tracking parameters in the URL: ${tracking.join(", ")}`,
        "Each different value is a different cache key, so every campaign link is a cold miss for the same page.",
        "Leave these parameters out of the cache key (on Cloudflare: a Cache Rule, Cache key, Query string, Exclude), or strip them at the edge.");
    }
    if (busters.length) {
      add("cache-buster", "info", `Possible cache buster in the URL: ${busters.join(", ")}`,
        "A parameter that changes on every request makes every request a miss.",
        "Use a content hash in the file name instead, and long lifetimes.");
    }
  } catch {
    // not a URL we can parse; nothing to say about its query
  }

  // 8. Per-visitor content: the two anonymous fetches should be identical.
  if (b && a.status === b.status && a.status === 200 && /^(text\/|application\/(json|xml|xhtml))/.test(type)) {
    const diffs = bodyDiffs(a.body, b.body);
    const kinds = new Map<string, Diff[]>();
    for (const d of diffs) {
      const k = classify(d);
      kinds.set(k, [...(kinds.get(k) ?? []), d]);
    }
    const tokens = kinds.get("token") ?? [];
    if (tokens.length) {
      add("csrf-token", "blocks", "The page carries a per-visitor form token (CSRF)",
        `Two anonymous requests got different tokens, for example after "${show(tokens[0]!.context)}": ${mask(tokens[0]!.a)} then ${mask(tokens[0]!.b)}. A cache would hand one visitor's token to everyone, and their forms would fail.`,
        "Fetch the token with JavaScript from a small uncached endpoint when the form is used, or use SameSite cookies plus a double-submit token set at the edge.");
    }
    const nonces = kinds.get("nonce") ?? [];
    const cspA = h["content-security-policy"] ?? "";
    const cspB = b.headers["content-security-policy"] ?? "";
    if (nonces.length || (cspA.includes("nonce-") && cspA !== cspB)) {
      add("csp-nonce", "blocks", "The page uses a fresh CSP nonce on every response",
        "A cached copy would serve the same nonce to everyone, which defeats the nonce. So the page cannot be cached as it is.",
        "Use script hashes instead of nonces, or have the edge put a fresh nonce into each cached copy (an HTMLRewriter in a Cloudflare Worker does this).");
    }
    const rest = [...(kinds.get("id") ?? []), ...(kinds.get("time") ?? []), ...(kinds.get("other") ?? [])];
    if (rest.length) {
      const d = rest[0]!;
      add("body-varies", tokens.length || nonces.length ? "info" : "hurts", `The body changes between two anonymous requests (${rest.length} place${rest.length > 1 ? "s" : ""})`,
        `For example after "${show(d.context)}": ${mask(d.a)} then ${mask(d.b)}. If this is a timestamp or request id it is harmless but means the page is built per request; if it is per-visitor data, caching would leak it.`,
        "Move per-request values out of the HTML (into headers or a small API call), so the page itself is the same for everyone.");
    }
  }

  // 9. What the CDN in front says, if there is one. A HIT is proof the CDN caches the page,
  // whatever the headers we see say: CDNs often get their own instructions from the origin
  // (Surrogate-Control, rules) and remove them before the response reaches a visitor.
  const cdnName = detectCdn(h);
  const statuses = [cacheStatus(h), b ? cacheStatus(b.headers) : ""].filter(Boolean);
  const last = (statuses[statuses.length - 1] ?? "").trim();
  const hit = Boolean(b) && servedFromCache(b!.headers, h, !opts.insideCloudflare);

  // A cached Set-Cookie: a stored response repeats ALL of its cookies, value for value. If any cookie
  // differs between the two hits, cookies are being set per request after the cache (an edge function
  // adding a visitor id), and the identical ones are just constants. Seen on real sites: a fresh visitor
  // id next to `consent=none` on both hits. Load balancer cookies are left out of the comparison: a balancer in front
  // of an origin cache issues a new one per response while the stored session cookie repeats underneath it.
  const pairs = (s: Snapshot) =>
    [...new Set(s.setCookies.map((c) => (c.split(";")[0] ?? "").trim()).filter((p) => p && !EDGE_COOKIES.test(cookieName(p)) && !LB_COOKIES.test(cookieName(p))))].sort();
  const pa = pairs(a);
  const pb = b ? pairs(b) : [];
  const repeated = hit && pa.length > 0 && pa.join("\n") === pb.join("\n");
  // Long enough to tell people apart: a session or visitor id, not "1", "none" or "en".
  const identifying = repeated ? pa.filter((p) => p.slice(p.indexOf("=") + 1).length >= 16).map(cookieName) : [];
  const leaked = identifying.length > 0;
  if (leaked) {
    add("cached-cookie", "blocks", `The cache hands the same cookie to every visitor: ${identifying.join(", ")}`,
      "Both requests were cache hits and came with exactly the same cookies, including values long enough to identify someone. Whoever filled the cache gave their cookie to every later visitor; if it is a session id, they all share one session.",
      "Do not set cookies on anonymous visits, or strip Set-Cookie at the edge before the response is stored. Then purge this URL from the cache.");
  } else if (repeated) {
    add("cached-cookie-constant", "hurts", `Every cached copy sets the same cookie: ${pa.map(cookieName).join(", ")}`,
      "Both requests were cache hits with exactly the same short cookie values (like 1 or none). Nobody's identity leaks, but each cached page view resets whatever the visitor's own cookie said.",
      "Set preference cookies from JavaScript or a small uncached request, not on the cached page.");
  }
  // Inside a Worker an Age with no status header may be Cloudflare's own subrequest cache, not the site's CDN.
  const ageOnly = cdnName === "a cache" && !STATUS_HEADERS.some((n) => h[n] || b?.headers[n]);
  if (cdnName) {
    const meaning = cdnName === "Cloudflare" ? CF_STATUS[last.toUpperCase()] : undefined;
    const said = ageOnly && opts.insideCloudflare
      ? "Only an Age header, and this web checker runs on Cloudflare, whose own subrequest cache can answer and set Age itself, so it is not counted as the site's cache."
      : "Cache status as reported by the CDN.";
    add("cdn", "info", `${cdnName} is in front${statuses.length ? `: ${statuses.join(", then ")}` : ""}`,
      (meaning ?? (hit ? "The second request was served from the cache." : said)) +
        (hit && !leaked ? " The other findings are about what browsers and any cache after the CDN see." : ""),
      leaked ? "Purge this URL once the cookie is gone." : hit ? "Nothing to fix at the CDN for this URL." : "Fix the blockers above; the CDN status should then turn into MISS and then HIT.");
  }

  const order: Record<Severity, number> = { blocks: 0, hurts: 1, info: 2 };
  f.sort((x, y) => order[x.severity] - order[y.severity]);
  const verdict = leaked
    ? "cached-unsafe"
    : hit
    ? "cached-at-cdn"
    : f.some((x) => x.severity === "blocks")
      ? "not-cacheable"
      : f.some((x) => x.severity === "hurts")
        ? "cacheable-with-issues"
        : "cacheable";
  return { url, verdict, ttl, cdn: cdnName ? { name: cdnName, status: statuses } : null, findings: f };
}
