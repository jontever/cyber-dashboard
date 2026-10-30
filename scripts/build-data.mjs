#!/usr/bin/env node
/**
 * Exploited-to-Control data build.
 *
 * Joins CISA KEV -> CWE -> CAPEC -> ATT&CK -> (D3FEND, NIST 800-53) -> NCSC CAF,
 * adds EPSS scores and Wikidata vendor identities, and writes static files to
 * public/data for the front end:
 *   dataset.json        everything the UI needs
 *   graph.jsonld        the same links as JSON-LD (linked open data)
 *   kev-enriched.csv    one row per CVE, for spreadsheets
 *   meta.json           build time, source versions, coverage, warnings
 */
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import { loadKev, loadEpss, loadAttack, loadCapec, loadCtid, loadD3fend, loadWikidata } from "./lib/sources.mjs";
import { toJsonLd } from "./lib/jsonld.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.join(ROOT, "public", "data");
const CACHE = path.join(ROOT, "data", "cache");
const SITE_URL = (process.env.SITE_URL ?? "https://exploited-to-control.vercel.app").replace(/\/$/, "");

const readYaml = async (p) => yaml.load(await readFile(path.join(ROOT, p), "utf8"));
const readCache = async (name) => (existsSync(path.join(CACHE, name)) ? JSON.parse(await readFile(path.join(CACHE, name), "utf8")) : {});
const writeJson = (p, o, pretty = false) => writeFile(p, JSON.stringify(o, null, pretty ? 2 : 0) + "\n");
const sortKeys = (o) => Object.fromEntries(Object.entries(o).sort(([a], [b]) => a.localeCompare(b)));

const SKIP_CWES = new Set(["NVD-CWE-Other", "NVD-CWE-noinfo", "CWE-20"]); // too generic to infer techniques from
const MAX_CAPEC = 8;

async function main() {
  const sources = await readYaml("config/sources.yaml");
  const cafMap = await readYaml("config/caf-mapping.yaml");
  const vendorsCfg = await readYaml("config/vendors.yaml");
  const rx = (s) => (s ? new RegExp(s, "i") : null);
  const rules = ((await readYaml("config/technique-rules.yaml")).rules ?? []).map((r) => ({
    ...r, text: rx(r.text), product: rx(r.product), not_product: rx(r.not_product),
  }));
  const meta = { generatedAt: new Date().toISOString(), siteUrl: SITE_URL, sources: {}, warnings: [], coverage: {} };
  const optional = async (name, fn) => {
    try {
      const r = await fn();
      meta.sources[name] = { ok: true, ...r.meta };
      return r;
    } catch (e) {
      if (sources[name]?.required) throw e;
      meta.sources[name] = { ok: false, error: String(e.message).slice(0, 300) };
      meta.warnings.push(`${name} unavailable this run: enrichment skipped.`);
      console.warn(`! ${name}: ${e.message}`);
      return null;
    }
  };

  // ------------------------------------------------------------ required sources
  console.log("Loading KEV, ATT&CK, CAPEC…");
  const [kev, attack, capec] = await Promise.all([loadKev(sources.kev), loadAttack(sources.attack), loadCapec(sources.capec)]);
  meta.sources.kev = { ok: true, url: kev.url, catalogVersion: kev.catalogVersion, dateReleased: kev.dateReleased, count: kev.vulns.length };
  meta.sources.attack = { ok: true, url: attack.url, version: attack.version };
  meta.sources.capec = { ok: true, url: capec.url, patterns: Object.keys(capec.capec).length };
  const cveIds = kev.vulns.map((v) => v.cveID);

  // ------------------------------------------------------------ optional sources
  console.log("Loading CTID mappings, EPSS…");
  const ctid = await optional("ctid", async () => {
    const r = await loadCtid(sources.ctid);
    return { ...r, meta: { kevFile: r.kevPath, nistFile: r.nistPath, autoDiscovered: r.discovered, kevSnapshot: r.kevMeta.snapshot, kevAttackVersion: r.kevMeta.attackVersion, nistAttackVersion: r.nistMeta.attackVersion } };
  });
  const epss = await optional("epss", async () => {
    const r = await loadEpss(sources.epss, cveIds);
    return { ...r, meta: { url: r.url, scoreDate: r.scoreDate, scored: r.scores.size } };
  });

  // ------------------------------------------------------------ technique resolution
  const resolveT = (id) => {
    let t = id, hops = 0;
    while (attack.revokedBy[t] && hops++ < 5) t = attack.revokedBy[t];
    return t;
  };

  const cves = [];
  const usedTechniques = new Set();
  const usedCapec = new Set();
  let direct = 0, inferred = 0, none = 0;

  for (const v of kev.vulns) {
    const techniques = [];
    const ctidRows = ctid?.cveToAttack[v.cveID] ?? [];
    if (ctidRows.length) {
      direct++;
      const seen = new Set();
      for (const r of ctidRows) {
        const id = resolveT(r.id);
        const key = `${id}|${r.type}`;
        if (seen.has(key)) continue;
        seen.add(key);
        techniques.push({ id, src: "ctid", type: r.type });
        if (!attack.techniques[id]) attack.techniques[id] ??= { name: r.name ?? id, tactics: [], external: true };
      }
    } else {
      // Heuristic rules from the KEV text and product (see config/technique-rules.yaml).
      const text = `${v.vulnerabilityName} ${v.shortDescription}`;
      const product = `${v.vendorProject} ${v.product}`;
      for (const r of rules) {
        if (r.text && !r.text.test(text)) continue;
        if (r.product && !r.product.test(product)) continue;
        if (r.not_product && r.not_product.test(product)) continue;
        if (r.unless?.some((u) => techniques.some((t) => t.id === u))) continue;
        for (const id of r.techniques) {
          if (!attack.techniques[id] || techniques.some((t) => t.id === id)) continue;
          techniques.push({ id, src: "rule", type: r.type, rule: r.id });
        }
      }
      if (techniques.length) inferred++; else none++;
    }
    techniques.forEach((t) => usedTechniques.add(t.id));

    // Context: attack patterns linked to the CVE's weaknesses (CWE -> CAPEC).
    const ap = [...new Set((v.cwes ?? []).filter((w) => !SKIP_CWES.has(w)).flatMap((w) => capec.cweToCapec[w] ?? []))]
      .sort((a, b) => +a.split("-")[1] - +b.split("-")[1]).slice(0, MAX_CAPEC);
    ap.forEach((c) => usedCapec.add(c));
    const e = epss?.scores.get(v.cveID);
    cves.push({
      id: v.cveID,
      v: v.vendorProject,
      p: v.product,
      n: v.vulnerabilityName,
      d: v.dateAdded,
      due: v.dueDate,
      rw: v.knownRansomwareCampaignUse === "Known",
      act: v.requiredAction,
      desc: v.shortDescription,
      cwe: v.cwes ?? [],
      ap,
      e: e ? +e.epss.toFixed(5) : null,
      ep: e ? +e.percentile.toFixed(5) : null,
      t: techniques,
    });
  }
  meta.coverage = { total: cves.length, directCtid: direct, heuristicRules: inferred, unmapped: none };

  // ------------------------------------------------------------ D3FEND + Wikidata (cached)
  await mkdir(CACHE, { recursive: true });
  const d3Cache = await readCache("d3fend.json");
  console.log(`Loading D3FEND for ${usedTechniques.size} techniques (cached)…`);
  await optional("d3fend", async () => {
    const r = await loadD3fend(sources.d3fend, [...usedTechniques].sort(), d3Cache);
    return { meta: { requestsThisRun: r.requests, failures: r.failures, cachedTechniques: Object.keys(d3Cache).length } };
  });
  await writeJson(path.join(CACHE, "d3fend.json"), sortKeys(d3Cache), true);

  const wdCache = await readCache("wikidata-vendors.json");
  const vendorNames = [...new Set(cves.map((c) => c.v))].sort();
  console.log(`Resolving ${vendorNames.length} vendors in Wikidata (cached)…`);
  await optional("wikidata", async () => {
    const r = await loadWikidata(sources.wikidata, vendorNames, vendorsCfg.overrides ?? {}, wdCache);
    return { meta: { requestsThisRun: r.requests, resolved: Object.values(wdCache).filter((x) => x.qid).length } };
  });
  // Overrides always apply, even when Wikidata is unreachable.
  for (const [name, qid] of Object.entries(vendorsCfg.overrides ?? {})) wdCache[name] = { ...(wdCache[name] ?? {}), qid, source: "override", checked: wdCache[name]?.checked ?? meta.generatedAt };
  await writeJson(path.join(CACHE, "wikidata-vendors.json"), sortKeys(wdCache), true);

  // ------------------------------------------------------------ technique dictionary + CAF
  const tacticCaf = cafMap.attack_tactics ?? {};
  const d3Caf = cafMap.d3fend_tactics ?? {};
  const techniques = {};
  for (const id of [...usedTechniques].sort()) {
    const t = attack.techniques[id];
    const d3 = d3Cache[id]?.items ?? [];
    techniques[id] = {
      name: t.name,
      tactics: t.tactics,
      ...(t.revoked || t.deprecated ? { stale: true } : {}),
      nist: [...new Set(ctid?.attackToNist[id] ?? [])].sort(),
      d3f: d3,
    };
  }
  for (const c of cves) {
    const caf = new Set(cafMap.always ?? []);
    for (const t of c.t) {
      const tech = techniques[t.id];
      for (const ta of tech?.tactics ?? []) (tacticCaf[ta] ?? []).forEach((x) => caf.add(x));
      for (const d of tech?.d3f ?? []) (d3Caf[d.tactic] ?? []).forEach((x) => caf.add(x));
    }
    c.caf = [...caf].sort();
  }

  const usedControls = new Set(Object.values(techniques).flatMap((t) => t.nist));
  const vendors = {};
  const watch = new Set(vendorsCfg.watchlist ?? []);
  for (const v of vendorNames) vendors[v] = { qid: wdCache[v]?.qid ?? null, watch: watch.has(v) };

  const dataset = {
    generatedAt: meta.generatedAt,
    attackVersion: attack.version,
    tactics: attack.tactics,
    cafOutcomes: cafMap.outcomes,
    cafMapping: { always: cafMap.always, attack_tactics: tacticCaf, d3fend_tactics: d3Caf },
    techniques,
    controls: Object.fromEntries([...usedControls].sort().map((k) => [k, ctid?.controls[k] ?? k])),
    capec: Object.fromEntries([...usedCapec].sort().map((k) => [k, capec.capec[k].name])),
    vendors,
    cves: cves.sort((a, b) => b.d.localeCompare(a.d) || b.id.localeCompare(a.id)),
  };

  // ------------------------------------------------------------ write outputs
  await mkdir(OUT, { recursive: true });
  await writeJson(path.join(OUT, "dataset.json"), dataset);
  await writeJson(path.join(OUT, "graph.jsonld"), toJsonLd(dataset, SITE_URL));
  await writeFile(path.join(OUT, "kev-enriched.csv"), toCsv(dataset));
  meta.coverage.withEpss = cves.filter((c) => c.e != null).length;
  meta.coverage.techniques = usedTechniques.size;
  meta.coverage.techniquesWithD3fend = Object.values(techniques).filter((t) => t.d3f.length).length;
  meta.coverage.vendorsWithQid = Object.values(vendors).filter((v) => v.qid).length;
  meta.coverage.vendors = vendorNames.length;
  await writeJson(path.join(OUT, "meta.json"), meta, true);
  console.log("Done:", JSON.stringify(meta.coverage));
  if (meta.warnings.length) console.log("Warnings:", meta.warnings.join(" "));
}

function toCsv(ds) {
  const esc = (s) => {
    const v = s == null ? "" : String(s);
    // Neutralise spreadsheet formula injection and quote as needed.
    const safe = /^[=+\-@\t\r]/.test(v) ? `'${v}` : v;
    return /[",\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
  };
  const head = ["cve", "vendor", "product", "name", "date_added", "due_date", "ransomware", "epss", "epss_percentile", "cwes",
    "attack_techniques", "technique_source", "d3fend", "nist_800_53", "caf_outcomes", "vendor_wikidata"];
  const rows = ds.cves.map((c) => {
    const tids = c.t.map((t) => t.id);
    const d3 = [...new Set(tids.flatMap((t) => ds.techniques[t]?.d3f.map((d) => d.label) ?? []))];
    const nist = [...new Set(tids.flatMap((t) => ds.techniques[t]?.nist ?? []))];
    return [c.id, c.v, c.p, c.n, c.d, c.due, c.rw ? "Known" : "Unknown", c.e, c.ep, c.cwe.join(" "), tids.join(" "),
      c.t[0]?.src ?? "", d3.join("; "), nist.join(" "), c.caf.join(" "), ds.vendors[c.v]?.qid ?? ""].map(esc).join(",");
  });
  return [head.join(","), ...rows].join("\n") + "\n";
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
