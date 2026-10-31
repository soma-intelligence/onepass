// Downloads the latest Tranco list and keeps the first 1000 hosts in rank order.
// Run once: node --experimental-strip-types lab/corpus/fetch-tranco.ts
import { writeFileSync } from "node:fs";

const COUNT = 1000;
const OUT = new URL("./tranco.json", import.meta.url);

async function get(url: string): Promise<Response> {
  const res = await fetch(url, { headers: { "user-agent": "OnePassLabCorpus/2 (+https://github.com/soma-intelligence/onepass)" } });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res;
}

const meta = (await (await get("https://tranco-list.eu/api/lists/date/latest")).json()) as { list_id?: string };
if (!meta.list_id) throw new Error("Tranco latest list has no list_id");
const csv = await (await get(`https://tranco-list.eu/download/${meta.list_id}/${COUNT}`)).text();
const hosts = csv.split(/\r?\n/).map((l) => l.split(",")[1]?.trim()).filter((h): h is string => !!h).slice(0, COUNT);
if (hosts.length !== COUNT) throw new Error(`expected ${COUNT} hosts, got ${hosts.length}`);
writeFileSync(OUT, JSON.stringify({ listId: meta.list_id, fetchedAt: new Date().toISOString(), hosts }, null, 2) + "\n");
console.log(`tranco ${meta.list_id}: ${hosts.length} hosts`);
