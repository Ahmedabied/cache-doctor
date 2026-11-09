// Run cache-doctor over a list of public homepages and print aggregate numbers:
// time to diagnose, verdicts, and how often each finding appears.
//   node bench/survey.ts bench/sites.txt
import { readFileSync } from "node:fs";
import { check, type Report } from "../src/probe.ts";

const sites = readFileSync(process.argv[2] ?? "bench/sites.txt", "utf8").split("\n").map((s) => s.trim()).filter((s) => s && !s.startsWith("#"));
const results: Report[] = [];
const failed: string[] = [];
let next = 0;
async function worker() {
  while (next < sites.length) {
    const site = sites[next++]!;
    try {
      results.push(await check(`https://${site}/`, { timeoutMs: 15000 }));
    } catch {
      failed.push(site);
    }
  }
}
await Promise.all(Array.from({ length: 6 }, worker));

const ms = results.map((r) => r.ms).sort((a, b) => a - b);
const pct = (q: number) => Math.round(ms[Math.min(ms.length - 1, Math.floor(q * ms.length))] ?? 0);
const count = (f: (r: Report) => boolean) => results.filter(f).length;
const share = (n: number) => `${n} (${Math.round((100 * n) / results.length)}%)`;
console.log(`${results.length} sites checked, ${failed.length} unreachable`);
console.log(`time to diagnose (two fetches): median ${pct(0.5)} ms, p90 ${pct(0.9)} ms`);
for (const v of ["cached-at-cdn", "cacheable", "cacheable-with-issues", "not-cacheable", "refused"]) {
  console.log(`verdict ${v}: ${share(count((r) => r.verdict === v))}`);
}
const ids = new Map<string, number>();
for (const r of results) for (const id of new Set(r.findings.map((f) => f.id))) ids.set(id, (ids.get(id) ?? 0) + 1);
for (const [id, n] of [...ids].sort((a, b) => b[1] - a[1])) console.log(`finding ${id}: ${share(n)}`);
