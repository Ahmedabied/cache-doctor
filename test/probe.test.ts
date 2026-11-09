import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { promisify } from "node:util";
import { check, snapshot } from "../src/probe.ts";

const run = promisify(execFile);
let server: Server;
let base = "";

before(async () => {
  server = createServer((req, res) => {
    const path = req.url ?? "/";
    if (path === "/static") {
      res.writeHead(200, { "content-type": "text/css", "cache-control": "public, max-age=31536000, immutable" });
      res.end("body{}");
    } else if (path === "/cookie") {
      res.writeHead(200, { "content-type": "text/html", "set-cookie": ["sid=1; HttpOnly", "ab=b"], "cache-control": "s-maxage=60" });
      res.end("<p>hi</p>");
    } else if (path === "/csrf") {
      const t = randomBytes(16).toString("hex");
      res.writeHead(200, { "content-type": "text/html", "cache-control": "public, s-maxage=60" });
      res.end(`<form><input type="hidden" name="csrf_token" value="${t}"></form>`);
    } else if (path === "/hop") {
      res.writeHead(301, { location: "/static" });
      res.end();
    } else if (path === "/big") {
      res.writeHead(200, { "content-type": "text/plain", "cache-control": "s-maxage=60" });
      res.end("x".repeat(2 * 1024 * 1024));
    } else if (path === "/cookies-sent") {
      res.writeHead(200, { "content-type": "application/json", "cache-control": "s-maxage=60" });
      res.end(JSON.stringify({ cookie: req.headers.cookie ?? null, auth: req.headers.authorization ?? null, ua: req.headers["user-agent"] }));
    } else {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("nope");
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => server.close());

test("a long-lived static file is cacheable", async () => {
  const r = await check(`${base}/static`);
  assert.equal(r.verdict, "cacheable");
  assert.equal(r.ttl, 31536000);
  assert.ok(r.ms >= 0);
});

test("cookies are reported by name", async () => {
  const r = await check(`${base}/cookie`);
  assert.equal(r.verdict, "not-cacheable");
  assert.match(r.findings[0]!.title, /sid, ab/);
});

test("a random CSRF token is caught across the two fetches", async () => {
  const r = await check(`${base}/csrf`);
  assert.deepEqual(r.findings.map((f) => f.id), ["csrf-token"]);
});

test("redirects are followed and reported", async () => {
  const r = await check(`${base}/hop`);
  assert.equal(r.status, 200);
  assert.equal(r.redirects.length, 1);
  assert.ok(r.findings.some((f) => f.id === "redirects"));
});

test("bodies are capped", async () => {
  const { snap } = await snapshot(`${base}/big`, { maxBytes: 64 * 1024 });
  assert.equal(snap.body.length, 64 * 1024);
});

test("the probe sends no cookies or credentials", async () => {
  const { snap } = await snapshot(`${base}/cookies-sent`);
  const seen = JSON.parse(snap.body);
  assert.equal(seen.cookie, null);
  assert.equal(seen.auth, null);
  assert.match(seen.ua, /^cache-doctor\//);
});

test("allow() can refuse a URL, redirects included", async () => {
  await assert.rejects(check(`${base}/hop`, { allow: (u) => { if (u.pathname === "/static") throw new Error("refused"); } }), /refused/);
});

test("cli: exit codes and json", async () => {
  const ok = await run(process.execPath, ["src/cli.ts", `${base}/static`]);
  assert.match(ok.stdout, /verdict: cacheable/);
  await assert.rejects(run(process.execPath, ["src/cli.ts", `${base}/cookie`]), (e: { code: number; stdout: string }) =>
    e.code === 1 && /BLOCKS/.test(e.stdout));
  const json = await run(process.execPath, ["src/cli.ts", `${base}/static`, "--json"]);
  assert.equal(JSON.parse(json.stdout).verdict, "cacheable");
  await assert.rejects(run(process.execPath, ["src/cli.ts", "http://127.0.0.1:1/"]), (e: { code: number }) => e.code === 2);
});
