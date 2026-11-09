import assert from "node:assert/strict";
import { test } from "node:test";
import { bodyDiffs, clean, diagnose, parseCacheControl, type Snapshot } from "../src/diagnose.ts";

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
