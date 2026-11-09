import assert from "node:assert/strict";
import { test } from "node:test";
import { bodyDiffs, clean, diagnose, httpDate, parseCacheControl, parseCacheStatus, servedFromCache, type Snapshot } from "../src/diagnose.ts";

function snap(headers: Record<string, string> = {}, opts: Partial<Snapshot> = {}): Snapshot {
  return {
    url: "https://shop.test/p",
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8", ...headers },
    setCookies: [],
    body: "<html><body>hello</body></html>",
    bytes: 32,
    ms: 1,
    ...opts,
  };
}

const ids = (d: ReturnType<typeof diagnose>) => d.findings.map((f) => f.id);
const run = (h: Record<string, string>, opts: Partial<Snapshot> = {}, url = "https://shop.test/p") =>
  diagnose(url, snap(h, opts), snap(h, opts));

test("a page with a shared lifetime and nothing else is cacheable", () => {
  const d = run({ "cache-control": "public, max-age=60, s-maxage=600" });
  assert.equal(d.verdict, "cacheable");
  assert.equal(d.ttl, 600);
  assert.deepEqual(ids(d), []);
});

test("no-store and private block", () => {
  assert.deepEqual(ids(run({ "cache-control": "no-store" })), ["no-store"]);
  const p = run({ "cache-control": "private, max-age=60" });
  assert.equal(p.verdict, "not-cacheable");
  assert.deepEqual(ids(p), ["private"]);
  assert.deepEqual(ids(run({ "cache-control": 'private="set-cookie", s-maxage=60' })), ["private-fields"]);
});

test("no-cache and zero lifetimes force a trip to the origin", () => {
  const withEtag = run({ "cache-control": "no-cache", etag: '"abc"' });
  const without = run({ "cache-control": "no-cache" });
  assert.equal(withEtag.verdict, "cacheable-with-issues");
  assert.match(withEtag.findings[0]!.detail, /quick 304/);
  assert.match(without.findings[0]!.detail, /downloads the whole response/);
  assert.deepEqual(ids(run({ "cache-control": "max-age=0" })), ["revalidate-always"]);
  const cdnOnly = run({ "cache-control": "max-age=0, s-maxage=300" });
  assert.equal(cdnOnly.verdict, "cacheable");
  assert.equal(cdnOnly.ttl, 300);
});

test("Expires in the past or invalid", () => {
  assert.ok(ids(run({ expires: "0" })).includes("expires-past"));
  assert.ok(ids(run({ expires: "Thu, 01 Jan 1970 00:00:00 GMT", date: "Mon, 09 Nov 2026 07:00:00 GMT" })).includes("expires-past"));
  assert.deepEqual(ids(run({ pragma: "no-cache", expires: "Mon, 09 Nov 2026 08:00:00 GMT", date: "Mon, 09 Nov 2026 07:00:00 GMT" })), ["pragma"]);
  const future = run({ expires: "Mon, 09 Nov 2026 08:00:00 GMT", date: "Mon, 09 Nov 2026 07:00:00 GMT" });
  assert.equal(future.ttl, 3600);
  assert.equal(future.verdict, "cacheable");
});

test("status codes", () => {
  assert.deepEqual(ids(run({}, { status: 302 })), ["status"]);
  assert.deepEqual(ids(run({ "cache-control": "s-maxage=60" }, { status: 302 })), []);
  assert.ok(!ids(run({ "cache-control": "s-maxage=60" }, { status: 404 })).includes("status"));
  assert.ok(ids(run({ "cache-control": "s-maxage=10" }, { status: 503 })).includes("error-status"));
});

test("cookies from the origin block, cookies from the edge do not", () => {
  const origin = run({ "cache-control": "s-maxage=60" }, { setCookies: ["sid=abc; Path=/; HttpOnly", "consent=0"] });
  assert.equal(origin.verdict, "not-cacheable");
  assert.match(origin.findings[0]!.title, /2 cookies.*sid, consent/);
  const edge = run({ "cache-control": "s-maxage=60" }, { setCookies: ["__cf_bm=x; path=/"] });
  assert.equal(edge.verdict, "cacheable");
  assert.deepEqual(ids(edge), ["edge-cookie"]);
});

test("Vary", () => {
  assert.deepEqual(ids(run({ "cache-control": "s-maxage=60", vary: "*" })), ["vary-star"]);
  assert.deepEqual(ids(run({ "cache-control": "s-maxage=60", vary: "Accept-Encoding, Cookie" })), ["vary-cookie"]);
  assert.deepEqual(ids(run({ "cache-control": "s-maxage=60", vary: "User-Agent" })), ["vary-user-agent"]);
  assert.deepEqual(ids(run({ "cache-control": "s-maxage=60", vary: "accept-language" })), ["vary-accept-language"]);
  assert.deepEqual(ids(run({ "cache-control": "s-maxage=60", vary: "Accept-Encoding" })), []);
  assert.deepEqual(ids(run({ "cache-control": "s-maxage=60", vary: "Authorization" })), ["vary-authorization"]);
});

test("no lifetime: HTML hurts, static files are fine", () => {
  assert.deepEqual(ids(run({})), ["no-lifetime"]);
  assert.deepEqual(ids(run({ "content-type": "text/css" })), ["no-lifetime-static"]);
  assert.deepEqual(ids(run({ "cache-control": "s-maxage=20" })), ["short-ttl"]);
});

test("query string noise", () => {
  const d = run({ "cache-control": "s-maxage=60" }, {}, "https://shop.test/p?utm_source=x&fbclid=y&_=1700000000&id=4");
  assert.deepEqual(ids(d), ["tracking-params", "cache-buster"]);
  assert.match(d.findings[0]!.title, /utm_source, fbclid/);
});

test("per-visitor CSRF token in the body blocks", () => {
  const page = (t: string) => `<html><form><input type="hidden" name="authenticity_token" value="${t}"></form></html>`;
  const d = diagnose("https://shop.test/p", snap({ "cache-control": "s-maxage=60" }, { body: page("Zk3x9a8b7c6d5e4f") }),
    snap({ "cache-control": "s-maxage=60" }, { body: page("Q1w2e3r4t5y6u7i8") }));
  assert.equal(d.verdict, "not-cacheable");
  assert.deepEqual(ids(d), ["csrf-token"]);
  assert.match(d.findings[0]!.detail, /authenticity_token/);
  assert.doesNotMatch(d.findings[0]!.detail, /Zk3x9a8b7c6d5e4f/); // token values are masked
  const meta = (t: string) => `<head><meta name="csrf-token" content="${t}"></head>`;
  assert.deepEqual(ids(diagnose("u", snap({}, { body: meta("aaaaaaaaaaaaaaaa") }), snap({}, { body: meta("bbbbbbbbbbbbbbbb") }))),
    ["csrf-token", "no-lifetime"]);
});

test("fresh CSP nonces block", () => {
  const h = (n: string) => ({ "cache-control": "s-maxage=60", "content-security-policy": `script-src 'nonce-${n}'` });
  const body = (n: string) => `<script nonce="${n}">go()</script>`;
  const d = diagnose("u", snap(h("r4nd0m1"), { body: body("r4nd0m1") }), snap(h("r4nd0m2"), { body: body("r4nd0m2") }));
  assert.deepEqual(ids(d), ["csp-nonce"]);
});

test("other body changes hurt, identical bodies are fine", () => {
  const t = (s: string) => `<footer>Rendered at 2026-11-09 07:00:${s}</footer>`;
  const d = diagnose("u", snap({ "cache-control": "s-maxage=60" }, { body: t("01") }), snap({ "cache-control": "s-maxage=60" }, { body: t("02") }));
  assert.deepEqual(ids(d), ["body-varies"]);
  assert.equal(d.findings[0]!.severity, "hurts");
});

test("targeted CDN-Cache-Control wins over Cache-Control for the CDN", () => {
  const d = run({ "cache-control": "private, no-cache", "cdn-cache-control": "max-age=600" });
  assert.equal(d.verdict, "cacheable");
  assert.equal(d.ttl, 600);
  assert.deepEqual(ids(d), ["targeted-cache-control"]);
});

test("an observed CDN hit is the verdict", () => {
  const miss = snap({ "cache-control": "private", "cf-cache-status": "MISS", "cf-ray": "1" });
  const hit = snap({ "cache-control": "private", "cf-cache-status": "HIT", "cf-ray": "1" });
  const d = diagnose("u", miss, hit);
  assert.equal(d.verdict, "cached-at-cdn");
  assert.deepEqual(d.cdn, { name: "Cloudflare", status: ["MISS", "HIT"] });
  const dyn = diagnose("u", snap({ "cf-cache-status": "DYNAMIC" }), snap({ "cf-cache-status": "DYNAMIC" }));
  assert.equal(dyn.verdict, "cacheable-with-issues");
  assert.match(dyn.findings.find((f) => f.id === "cdn")!.detail, /static file types only/);
  const fastly = diagnose("u", snap({ "x-served-by": "cache-lhr123", "x-cache": "MISS" }), snap({ "x-served-by": "cache-lhr123", "x-cache": "HIT" }));
  assert.equal(fastly.cdn?.name, "Fastly");
  assert.equal(fastly.verdict, "cached-at-cdn");
});

test("parseCacheControl", () => {
  const cc = parseCacheControl('Public, max-age=60, private="set-cookie, x-id", s-maxage="120"');
  assert.equal(cc.get("public"), true);
  assert.equal(cc.get("max-age"), "60");
  assert.equal(cc.get("private"), "set-cookie, x-id");
  assert.equal(cc.get("s-maxage"), "120");
  assert.equal(parseCacheControl(undefined).size, 0);
});

test("bodyDiffs stays fast on big pages", () => {
  const big = "<p>x</p>".repeat(250_000);
  const t0 = performance.now();
  const d = bodyDiffs(big + "<i>1</i>" + big, big + "<i>2</i>" + big);
  assert.equal(d.length, 1);
  assert.ok(performance.now() - t0 < 1500);
});

test("server text cannot carry terminal escapes into findings", () => {
  const d = run({ "cache-control": "s-maxage=60" }, { setCookies: ["\u001b[2Jevil‮=1"] });
  assert.doesNotMatch(d.findings[0]!.title, /[\u001b‮]/);
  assert.equal(clean("ok\u0007"), "ok\\u0007");
});

test("a refused check is not diagnosed as the page", () => {
  for (const status of [403, 419, 429]) {
    const d = run({ "content-type": "text/html" }, { status });
    assert.equal(d.verdict, "refused");
    assert.deepEqual(ids(d), ["refused"]);
  }
  const challenge = run({ "cf-mitigated": "challenge" }, { status: 503 });
  assert.equal(challenge.verdict, "refused");
});

test("inside a Worker, headers Cloudflare adds to every fetch are ignored", () => {
  // Measured on the live Worker: a fetch of a site on Fastly came back with
  // server: cloudflare and cf-cache-status: DYNAMIC added by Cloudflare itself.
  const added = { "cache-control": "s-maxage=60", "cf-cache-status": "DYNAMIC", "cf-ray": "1", server: "cloudflare" };
  assert.equal(diagnose("u", snap(added), snap(added)).cdn?.name, "Cloudflare"); // from a laptop it is real
  const inside = diagnose("u", snap(added), snap(added), { insideCloudflare: true });
  assert.equal(inside.cdn, null);
  assert.equal(inside.verdict, "cacheable");
  const fastly = { ...added, "x-served-by": "cache-lhr1", "x-cache": "HIT" };
  const f = diagnose("u", snap(fastly), snap(fastly), { insideCloudflare: true });
  assert.equal(f.cdn?.name, "Fastly");
  assert.deepEqual(f.cdn?.status, ["HIT", "HIT"]);
});

test("a hit that hands every visitor the same cookie is a blocker, not a pass", () => {
  const h = { "cache-control": "public, s-maxage=600", "x-cache": "Hit from cloudfront", "x-amz-cf-id": "a" };
  const same = ["sessionid=SAME123; Path=/; HttpOnly", "__cf_bm=edge1; Path=/"];
  const d = diagnose("u", snap(h, { setCookies: same }), snap(h, { setCookies: same }));
  assert.equal(d.verdict, "cached-unsafe");
  const leak = d.findings.find((f) => f.id === "cached-cookie")!;
  assert.equal(leak.severity, "blocks");
  assert.match(leak.title, /sessionid/);
  assert.doesNotMatch(leak.title, /__cf_bm/); // edge cookies are added after the cache
  // A different value on the second request means the cookie is set per request, not stored.
  const fresh = diagnose("u", snap(h, { setCookies: ["sessionid=A1"] }), snap(h, { setCookies: ["sessionid=B2"] }));
  assert.equal(fresh.verdict, "cached-at-cdn");
  assert.ok(!ids(fresh).includes("cached-cookie"));
  // The same edge cookie on both is not a leak either.
  const edge = diagnose("u", snap(h, { setCookies: ["__cf_bm=x"] }), snap(h, { setCookies: ["__cf_bm=x"] }));
  assert.equal(edge.verdict, "cached-at-cdn");
});

test("hit-for-pass is a miss, in X-Cache and in Cache-Status", () => {
  assert.equal(servedFromCache({ "x-cache": "HIT-FOR-PASS" }), false);
  assert.equal(servedFromCache({ "x-cache": "hitpass" }), false);
  assert.equal(servedFromCache({ "x-cache": "MISS, HIT" }), true);
  assert.equal(servedFromCache({ "x-cache": "Hit from cloudfront" }), true);
  assert.equal(servedFromCache({ "x-cache": "RefreshHit from cloudfront" }), true);
  assert.equal(servedFromCache({ "x-cache": "TCP_MEM_HIT" }), true);
  assert.equal(servedFromCache({ "cf-cache-status": "EXPIRED" }), false);
  assert.equal(servedFromCache({ "cache-status": 'ExampleCache; fwd=uri-miss; detail="hit-for-pass"' }), false);
  assert.equal(servedFromCache({ "cache-status": "ExampleCache; hit" }), true);
  assert.equal(servedFromCache({ "cache-status": "ExampleCache; hit=?0" }), false);
  assert.equal(servedFromCache({ "cache-status": "OriginCache; hit; ttl=30, CDN; fwd=uri-miss; stored" }), true);
  const h = { "cache-control": "private", "x-cache": "HIT-FOR-PASS", age: "0" };
  assert.equal(diagnose("u", snap(h), snap(h)).verdict, "not-cacheable");
});

test("parseCacheStatus reads the RFC 9211 list, quoted strings included", () => {
  const list = parseCacheStatus('"Cache, Inc; EU"; hit; ttl=12, Edge; fwd=vary-miss; key="a,b;c"; collapsed=?1');
  assert.equal(list.length, 2);
  assert.equal(list[0]!.cache, "Cache, Inc; EU");
  assert.equal(list[0]!.params.get("hit"), true);
  assert.equal(list[0]!.params.get("ttl"), "12");
  assert.equal(list[1]!.params.get("fwd"), "vary-miss");
  assert.equal(list[1]!.params.get("key"), "a,b;c");
  assert.equal(list[1]!.params.get("collapsed"), true);
});

test("private and no-cache naming Set-Cookie are the standard fix, not a blocker", () => {
  for (const cc of ['public, s-maxage=600, private="Set-Cookie"', 'public, s-maxage=600, no-cache="Set-Cookie"']) {
    const d = run({ "cache-control": cc }, { setCookies: ["consent=1; Path=/"] });
    assert.equal(d.verdict, "cacheable-with-issues", cc);
    assert.ok(ids(d).includes("set-cookie-dropped") && !ids(d).includes("set-cookie"), cc);
    assert.equal(d.findings.find((f) => f.id === "set-cookie-dropped")!.severity, "hurts");
    assert.ok(ids(d).includes(cc.includes("private") ? "private-fields" : "no-cache-fields"), cc);
  }
  // Naming some other header leaves the cookie blocker in place.
  const other = run({ "cache-control": 'public, s-maxage=600, private="X-User"' }, { setCookies: ["sid=1"] });
  assert.ok(ids(other).includes("set-cookie"));
});

test("httpDate accepts the three HTTP date forms and nothing else", () => {
  const t = Date.UTC(1994, 10, 6, 8, 49, 37);
  assert.equal(httpDate("Sun, 06 Nov 1994 08:49:37 GMT"), t);
  assert.equal(httpDate("Sunday, 06-Nov-94 08:49:37 GMT", Date.UTC(2026, 0, 1)), t);
  assert.equal(httpDate("Sun Nov  6 08:49:37 1994"), t);
  // Two-digit year more than 50 years ahead is the century before.
  assert.equal(new Date(httpDate("Monday, 01-Jan-80 00:00:00 GMT", Date.UTC(2026, 0, 1))!).getUTCFullYear(), 1980);
  assert.equal(new Date(httpDate("Monday, 01-Jan-30 00:00:00 GMT", Date.UTC(2026, 0, 1))!).getUTCFullYear(), 2030);
  for (const bad of ["2030", "0", "-1", "Sun, 31 Feb 2030 00:00:00 GMT", "sun, 06 nov 1994 08:49:37 gmt", "Sun, 06 Nov 1994 25:00:00 GMT", ""]) {
    assert.equal(httpDate(bad), null, bad);
  }
});

test("an Expires that is not an HTTP date means already expired", () => {
  const d = run({ expires: "2030", date: "Mon, 09 Nov 2026 07:00:00 GMT" });
  assert.equal(d.ttl, 0);
  assert.ok(ids(d).includes("expires-past"));
});

test("a broken max-age counts as stale", () => {
  for (const cc of ["public, max-age=abc", "public, s-maxage"]) {
    const d = run({ "cache-control": cc });
    assert.equal(d.ttl, 0, cc);
    assert.deepEqual(ids(d), ["broken-lifetime"], cc);
  }
});

test("public lets a cache store a redirect and guess its lifetime", () => {
  const d = diagnose("u", snap({ "cache-control": "public" }, { status: 302 }));
  assert.ok(!ids(d).includes("status"));
  assert.ok(ids(d).includes("no-lifetime"));
  assert.ok(ids(diagnose("u", snap({}, { status: 302 }))).includes("status"));
});

test("Cloudflare errors (520 to 530) are not diagnosed as the site", () => {
  for (const status of [520, 522, 530]) {
    const d = diagnose("u", snap({ "cache-control": "no-store" }, { status }));
    assert.equal(d.verdict, "refused");
    assert.deepEqual(ids(d), ["refused"]);
  }
});
