#!/usr/bin/env node
// cache-doctor <url> [--json] [--timeout ms]
// Exit code: 0 cached or cacheable (maybe with issues), 1 not cacheable, 2 error.

import { clean } from "./diagnose.ts";
import { check, type Report } from "./probe.ts";

const color = process.stdout.isTTY && !process.env["NO_COLOR"];
const paint = (code: string, s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
const LABEL = { blocks: paint("1;31", "BLOCKS"), hurts: paint("1;33", "HURTS "), info: paint("2", "info  ") };
const VERDICT = {
  "cached-at-cdn": paint("1;32", "cached at the CDN (seen as a hit)"),
  "not-cacheable": paint("1;31", "not cacheable at a shared cache"),
  "cacheable-with-issues": paint("1;33", "cacheable, but with problems"),
  cacheable: paint("1;32", "cacheable"),
};

function wrap(text: string, indent: string, width = 100): string {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let line = "";
  for (const w of words) {
    if ((line + " " + w).trim().length > width - indent.length) {
      lines.push(line.trim());
      line = w;
    } else line += " " + w;
  }
  if (line.trim()) lines.push(line.trim());
  return lines.map((l) => indent + l).join("\n");
}

export function render(r: Report): string {
  const blocks = r.findings.filter((f) => f.severity === "blocks").length;
  const hurts = r.findings.filter((f) => f.severity === "hurts").length;
  const out = [
    paint("1", clean(r.url)),
    `  verdict: ${VERDICT[r.verdict]}` +
      (blocks || hurts
        ? r.verdict === "cached-at-cdn"
          ? ` (${blocks} blocking and ${hurts} hurting for browsers and caches after the CDN)`
          : ` (${blocks} blocking, ${hurts} hurting)`
        : ""),
    `  status ${r.status}, ${clean(r.contentType.split(";")[0] ?? "") || "no content type"}, ${(r.bytes / 1024).toFixed(1)} KB,` +
      ` shared lifetime ${r.ttl === null ? "not set" : `${r.ttl} s`}, checked in ${Math.round(r.ms)} ms`,
    "",
  ];
  for (const f of r.findings) {
    out.push(`  ${LABEL[f.severity]}  ${paint("1", f.title)}`);
    out.push(wrap(f.detail, "          "));
    out.push(wrap(`fix: ${f.fix}`, "          "));
    out.push("");
  }
  return out.join("\n");
}

async function main(argv: string[]): Promise<number> {
  const args = argv.slice(2);
  if (!args.length || args.includes("-h") || args.includes("--help")) {
    console.log("usage: cache-doctor <url> [--json] [--timeout ms]\n\nExplains why a URL can or cannot be served from a CDN cache.");
    return args.length ? 0 : 2;
  }
  const json = args.includes("--json");
  const t = args.indexOf("--timeout");
  const timeoutMs = t >= 0 ? Number(args[t + 1]) : 10000;
  const url = args.find((a, i) => !a.startsWith("--") && args[i - 1] !== "--timeout");
  if (!url) {
    console.error("cache-doctor: give a URL");
    return 2;
  }
  let target: URL;
  try {
    target = new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`);
  } catch {
    console.error(`cache-doctor: not a URL: ${url}`);
    return 2;
  }
  try {
    const r = await check(target.toString(), { timeoutMs });
    console.log(json ? JSON.stringify(r, null, 2) : render(r));
    return r.verdict === "not-cacheable" ? 1 : 0;
  } catch (e) {
    console.error(`cache-doctor: ${target}: ${(e as Error).message}`);
    return 2;
  }
}

const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].split("/").pop() ?? "");
if (isMain) main(process.argv).then((code) => process.exit(code));
