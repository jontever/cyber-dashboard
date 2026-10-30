#!/usr/bin/env node
/**
 * Builds RSS 2.0 feeds from public/data/dataset.json. Runs before `next build`,
 * so the feeds always match the data being deployed.
 *
 *   Each feed holds everything added in the last 30 days (at least the 20 newest).
 *
 *   /feed.xml              every vulnerability added to KEV
 *   /feed-ransomware.xml   only those with known ransomware use
 *   /feed-watchlist.xml    only vendors on the watchlist (config/vendors.yaml)
 */
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SITE = (process.env.SITE_URL || "https://www.cyberteam.uk").replace(/\/$/, "");
const DAYS = 30;
const MAX_ITEMS = 100;
const MIN_ITEMS = 20;
const NAME = "Exploited Vulnerabilities Dashboard";

const FEEDS = [
  { file: "feed.xml", title: `${NAME}: newly exploited vulnerabilities`, desc: `Vulnerabilities newly added to the CISA KEV catalogue, mapped to ATT&CK, D3FEND, NIST 800-53 and NCSC CAF.`, filter: () => true },
  { file: "feed-ransomware.xml", title: `${NAME}: known ransomware use`, desc: `Exploited vulnerabilities that CISA records as used in ransomware campaigns, newest first.`, filter: (c) => c.rw },
  { file: "feed-watchlist.xml", title: `${NAME}: vendor watchlist`, desc: `Newly exploited vulnerabilities in products from vendors on the watchlist.`, filter: (c, ds) => ds.vendors[c.v]?.watch },
];

const esc = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const cdata = (s) => `<![CDATA[${String(s).replace(/]]>/g, "]]]]><![CDATA[>")}]]>`;
const rfc822 = (d) => new Date(d).toUTCString();
const pct = (x) => (x == null ? "not available" : `${(x * 100).toFixed(x < 0.1 ? 1 : 0)}%`);

function itemHtml(c, ds) {
  const techs = c.t.map((t) => `${t.id} ${ds.techniques[t.id]?.name ?? ""}${t.src === "ctid" ? "" : " (heuristic)"}`);
  const d3 = [...new Set(c.t.flatMap((t) => (ds.techniques[t.id]?.d3f ?? []).map((d) => d.label)))].slice(0, 8);
  const caf = c.caf.map((k) => `${k} ${ds.cafOutcomes[k] ?? ""}`);
  const row = (k, v) => (v ? `<tr><td><b>${esc(k)}</b></td><td>${v}</td></tr>` : "");
  return [
    `<p>${esc(c.desc)}</p>`,
    "<table>",
    row("Vendor / product", esc(`${c.v} ${c.p}`)),
    row("Added to KEV", esc(c.d)),
    row("Known ransomware use", c.rw ? "<b>Yes</b>" : "Unknown"),
    row("EPSS", esc(pct(c.e))),
    row("ATT&CK techniques", esc(techs.join("; ")) || "Not yet mapped"),
    row("D3FEND countermeasures", esc(d3.join("; "))),
    row("NCSC CAF outcomes", esc(caf.join("; "))),
    row("CISA required action", esc(c.act)),
    "</table>",
    `<p><a href="${esc(`${SITE}/explore/?cve=${c.id}`)}">See the full chain on the dashboard</a> · <a href="${esc(`https://www.cve.org/CVERecord?id=${c.id}`)}">CVE record</a></p>`,
  ].join("");
}

function buildFeed(feed, ds) {
  const ref = new Date(ds.generatedAt);
  ref.setUTCDate(ref.getUTCDate() - DAYS);
  const cutoff = ref.toISOString().slice(0, 10);
  const matching = ds.cves
    .filter((c) => feed.filter(c, ds))
    .sort((a, b) => b.d.localeCompare(a.d) || b.id.localeCompare(a.id));
  // Everything from the last DAYS days, topped up with older items so a quiet
  // feed (e.g. ransomware) is never empty for a new subscriber.
  const recent = matching.filter((c) => c.d >= cutoff);
  const items = (recent.length >= MIN_ITEMS ? recent : matching.slice(0, MIN_ITEMS)).slice(0, MAX_ITEMS);
  const self = `${SITE}/${feed.file}`;
  const body = items.map((c) => {
    const cats = [c.v, ...c.caf, ...c.t.map((t) => t.id), ...(c.rw ? ["Ransomware"] : [])];
    return [
      "    <item>",
      `      <title>${esc(`${c.id}: ${c.n}${c.rw ? " [ransomware]" : ""}`)}</title>`,
      `      <link>${esc(`${SITE}/explore/?cve=${c.id}`)}</link>`,
      `      <guid isPermaLink="false">${esc(c.id)}</guid>`,
      `      <pubDate>${rfc822(`${c.d}T00:00:00Z`)}</pubDate>`,
      ...[...new Set(cats)].map((x) => `      <category>${esc(x)}</category>`),
      `      <description>${cdata(itemHtml(c, ds))}</description>`,
      "    </item>",
    ].join("\n");
  });
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">',
    "  <channel>",
    `    <title>${esc(feed.title)}</title>`,
    `    <link>${esc(`${SITE}/`)}</link>`,
    `    <atom:link href="${esc(self)}" rel="self" type="application/rss+xml"/>`,
    `    <description>${esc(feed.desc)}</description>`,
    "    <language>en-gb</language>",
    `    <lastBuildDate>${rfc822(ds.generatedAt)}</lastBuildDate>`,
    "    <ttl>360</ttl>",
    `    <image><url>${esc(`${SITE}/apple-icon.png`)}</url><title>${esc(feed.title)}</title><link>${esc(`${SITE}/`)}</link></image>`,
    ...body,
    "  </channel>",
    "</rss>",
    "",
  ].join("\n");
}

const ds = JSON.parse(await readFile(path.join(ROOT, "public", "data", "dataset.json"), "utf8"));
for (const feed of FEEDS) {
  const xml = buildFeed(feed, ds);
  await writeFile(path.join(ROOT, "public", feed.file), xml);
  console.log(`${feed.file}: ${(xml.match(/<item>/g) ?? []).length} items`);
}
