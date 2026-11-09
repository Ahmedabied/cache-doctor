// The demo page: one HTML file, one stylesheet, one script. No outside requests, no tracking.

export const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>cache-doctor: why is this page not cached?</title>
<meta name="description" content="Give it a URL. It explains every reason the response cannot be shared from a CDN cache, with the fix for each.">
<link rel="stylesheet" href="/style.css">
<script src="/app.js" defer></script>
</head>
<body>
<main>
  <header>
    <p class="eyebrow">cache-doctor</p>
    <h1>Why isn't this page cached?</h1>
    <p class="lede">Give it a URL. It asks for the page twice, the way a CDN sees a first-time visitor, and explains every reason the response cannot be shared from a cache, with the fix for each.</p>
  </header>
  <form id="f" action="/" method="get">
    <input id="u" name="url" type="text" inputmode="url" autocomplete="url" spellcheck="false" placeholder="example.com/some/page" aria-label="URL to check" required>
    <button type="submit">Check</button>
  </form>
  <p class="try">Try
    <button type="button" class="chip" data-u="news.ycombinator.com">news.ycombinator.com</button>
    <button type="button" class="chip" data-u="github.com">github.com</button>
    <button type="button" class="chip" data-u="www.gov.uk">www.gov.uk</button>
  </p>
  <section id="out" aria-live="polite"></section>
  <footer>
    <p>Open source, MIT: <a href="https://github.com/Ahmedabied/cache-doctor">github.com/Ahmedabied/cache-doctor</a>. It is also a command line tool.</p>
    <p>Only the diagnosis comes back, never the page. Each URL is checked at most once a minute; repeats come from the cache. This page passes its own check.</p>
  </footer>
</main>
</body>
</html>
`;

const MONO = `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`;

export const STYLE_CSS = `:root {
  --bg: #f6f5f2; --fg: #1b1b1a; --muted: #6a6862; --card: #ffffff; --line: #e4e1da;
  --block: #c2410c; --hurt: #a86b12; --info: #7a8593; --ok: #2c7a51; --accent: #1f4e79;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #111214; --fg: #ebebea; --muted: #9b9a96; --card: #1a1c1f; --line: #2b2e33;
    --block: #f2773b; --hurt: #e3aa48; --info: #8d99a8; --ok: #5cc28d; --accent: #8cbbe8;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 16px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; -webkit-font-smoothing: antialiased; }
main { max-width: 760px; margin: 0 auto; padding: 72px 24px 48px; }
.eyebrow { font: 600 12px/1 ${MONO}; letter-spacing: .12em; text-transform: uppercase; color: var(--accent); margin: 0 0 14px; }
h1 { font-size: 42px; line-height: 1.1; letter-spacing: -.025em; margin: 0 0 16px; font-weight: 700; }
.lede { color: var(--muted); font-size: 18px; margin: 0 0 32px; max-width: 640px; }
form { display: flex; gap: 10px; }
input { flex: 1; min-width: 0; font: 15px ${MONO}; padding: 14px 16px; border: 1px solid var(--line);
  border-radius: 10px; background: var(--card); color: var(--fg); outline: none; }
input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 22%, transparent); }
button[type=submit] { font: 600 15px/1 inherit; padding: 0 24px; border: 0; border-radius: 10px;
  background: var(--fg); color: var(--bg); cursor: pointer; }
button[disabled] { opacity: .5; cursor: progress; }
.try { color: var(--muted); font-size: 14px; margin: 14px 0 44px; }
.chip { font: 13px ${MONO}; background: transparent; border: 1px solid var(--line); border-radius: 999px;
  padding: 4px 11px; color: var(--fg); cursor: pointer; margin: 0 2px; }
.chip:hover { border-color: var(--accent); }
.verdict { border-radius: 12px; padding: 20px 22px; margin: 0 0 18px; background: var(--card); border: 1px solid var(--line); }
.verdict h2 { margin: 0 0 6px; font-size: 22px; letter-spacing: -.01em; }
.meta { color: var(--muted); font: 13px/1.6 ${MONO}; margin: 0; overflow-wrap: anywhere; }
.v-not-cacheable h2 { color: var(--block); }
.v-cacheable-with-issues h2 { color: var(--hurt); }
.v-cacheable h2, .v-cached-at-cdn h2 { color: var(--ok); }
.finding { background: var(--card); border: 1px solid var(--line); border-left: 4px solid var(--info);
  border-radius: 10px; padding: 16px 18px; margin: 0 0 12px; }
.finding.blocks { border-left-color: var(--block); }
.finding.hurts { border-left-color: var(--hurt); }
.tag { display: inline-block; font: 700 11px/1 ${MONO}; letter-spacing: .06em; text-transform: uppercase;
  padding: 4px 7px; border-radius: 5px; margin-right: 10px; vertical-align: 2px; color: #fff; background: var(--info); }
.blocks .tag { background: var(--block); }
.hurts .tag { background: var(--hurt); }
.finding h3 { display: inline; font-size: 16px; margin: 0; overflow-wrap: anywhere; }
.finding p { margin: 8px 0 0; overflow-wrap: anywhere; }
.fix { margin-top: 12px; padding: 10px 12px; border-radius: 8px; font-size: 15px;
  background: color-mix(in srgb, var(--ok) 10%, transparent); }
.fix b { color: var(--ok); }
.error { color: var(--block); }
footer { margin-top: 64px; color: var(--muted); font-size: 14px; border-top: 1px solid var(--line); padding-top: 20px; }
footer p { margin: 0 0 6px; }
a { color: var(--accent); }
@media (max-width: 560px) { h1 { font-size: 31px; } main { padding-top: 44px; } form { flex-direction: column; } button[type=submit] { padding: 14px; } }
`;

export const APP_JS = `"use strict";
const $ = (s) => document.querySelector(s);
const form = $("#f"), input = $("#u"), out = $("#out"), button = form.querySelector("button[type=submit]");
const LABEL = { blocks: "Blocks", hurts: "Hurts", info: "Info" };
const VERDICT = {
  "not-cacheable": "Not cacheable at a shared cache",
  "cacheable-with-issues": "Cacheable, but with problems",
  "cacheable": "Cacheable",
  "cached-at-cdn": "Cached at the CDN",
};

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text; // never innerHTML: the text comes from other people's servers
  return e;
}

function render(d) {
  const v = el("div", "verdict v-" + d.verdict);
  v.append(el("h2", null, VERDICT[d.verdict] || d.verdict));
  const type = (d.contentType || "").split(";")[0] || "no content type";
  const ttl = d.ttl == null ? "not set" : d.ttl + " s";
  const cdn = d.cdn ? " \\u00b7 " + d.cdn.name : "";
  v.append(el("p", "meta", "status " + d.status + " \\u00b7 " + type + " \\u00b7 shared lifetime " + ttl + cdn + " \\u00b7 checked in " + Math.round(d.ms) + " ms"));
  v.append(el("p", "meta", d.url));
  const items = [v];
  for (const f of d.findings) {
    const c = el("article", "finding " + f.severity);
    c.append(el("span", "tag", LABEL[f.severity] || f.severity), el("h3", null, f.title), el("p", null, f.detail));
    const fix = el("div", "fix");
    fix.append(el("b", null, "Fix: "), document.createTextNode(f.fix));
    c.append(fix);
    items.push(c);
  }
  if (!d.findings.length) items.push(el("p", "meta", "Nothing found. A shared cache can store this response."));
  out.replaceChildren(...items);
}

async function run(url) {
  button.disabled = true;
  out.replaceChildren(el("p", "meta", "Checking " + url + " ..."));
  history.replaceState(null, "", "?url=" + encodeURIComponent(url));
  try {
    const r = await fetch("/api/check?url=" + encodeURIComponent(url));
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || "HTTP " + r.status);
    render(d);
  } catch (e) {
    out.replaceChildren(el("p", "error", e.message));
  } finally {
    button.disabled = false;
  }
}

form.addEventListener("submit", (e) => { e.preventDefault(); const u = input.value.trim(); if (u) run(u); });
document.querySelectorAll(".chip").forEach((b) => b.addEventListener("click", () => { input.value = b.dataset.u; run(b.dataset.u); }));
const q = new URLSearchParams(location.search).get("url");
if (q) { input.value = q; run(q); }
`;
