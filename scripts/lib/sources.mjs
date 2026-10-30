import { firstWorking, fetchRetry, asJson, asText, asGunzipText, sleep } from "./net.mjs";

// ---------------------------------------------------------------- KEV
export async function loadKev(cfg) {
  const { url, data } = await firstWorking(cfg.urls, asJson);
  if (!Array.isArray(data?.vulnerabilities)) throw new Error("KEV: unexpected format");
  return { url, catalogVersion: data.catalogVersion, dateReleased: data.dateReleased, vulns: data.vulnerabilities };
}

// ---------------------------------------------------------------- EPSS
export async function loadEpss(cfg, cveIds) {
  const want = new Set(cveIds);
  // 1. Full daily CSV
  try {
    const { url, data } = await firstWorking(cfg.csv_gz_urls, asGunzipText, { timeoutMs: 120000 });
    const scores = new Map();
    let scoreDate = null;
    for (const line of data.split("\n")) {
      if (line.startsWith("#")) {
        scoreDate = line.match(/score_date:([0-9T:\-+Z.]+)/)?.[1] ?? scoreDate;
        continue;
      }
      const [cve, epss, pct] = line.split(",");
      if (want.has(cve)) scores.set(cve, { epss: +epss, percentile: +pct });
    }
    if (scores.size) return { url, scoreDate, scores };
  } catch (e) {
    console.warn(`EPSS CSV failed, trying API: ${e.message}`);
  }
  // 2. API in batches of 100
  const scores = new Map();
  let scoreDate = null;
  const ids = [...want];
  for (let i = 0; i < ids.length; i += 100) {
    const batch = ids.slice(i, i + 100);
    const res = await fetchRetry(`${cfg.api_url}?cve=${batch.join(",")}&limit=100`);
    const json = await res.json();
    for (const r of json.data ?? []) {
      scores.set(r.cve, { epss: +r.epss, percentile: +r.percentile });
      scoreDate ??= r.date;
    }
    await sleep(300);
  }
  return { url: cfg.api_url, scoreDate, scores };
}

// ---------------------------------------------------------------- ATT&CK
const extId = (o, source) => o.external_references?.find((r) => r.source_name === source)?.external_id;

export async function loadAttack(cfg) {
  const { url, data } = await firstWorking(cfg.urls, asJson, { timeoutMs: 180000 });
  const objs = data.objects ?? [];
  const collection = objs.find((o) => o.type === "x-mitre-collection");
  const tactics = {};
  for (const o of objs.filter((o) => o.type === "x-mitre-tactic")) {
    tactics[o.x_mitre_shortname] = { id: extId(o, "mitre-attack"), name: o.name };
  }
  const byStix = new Map();
  const techniques = {};
  for (const o of objs.filter((o) => o.type === "attack-pattern")) {
    const id = extId(o, "mitre-attack");
    if (!id) continue;
    byStix.set(o.id, id);
    techniques[id] = {
      name: o.name,
      tactics: (o.kill_chain_phases ?? []).filter((k) => k.kill_chain_name === "mitre-attack").map((k) => k.phase_name),
      revoked: !!o.revoked,
      deprecated: !!o.x_mitre_deprecated,
    };
  }
  // Follow revoked-by so old IDs from older mapping sets resolve to current ones.
  const revokedBy = {};
  for (const r of objs.filter((o) => o.type === "relationship" && o.relationship_type === "revoked-by")) {
    const from = byStix.get(r.source_ref);
    const to = byStix.get(r.target_ref);
    if (from && to) revokedBy[from] = to;
  }
  return { url, version: collection?.x_mitre_version ?? null, tactics, techniques, revokedBy };
}

// ---------------------------------------------------------------- CAPEC (CWE -> CAPEC -> ATT&CK)
export async function loadCapec(cfg) {
  const { url, data } = await firstWorking(cfg.urls, asJson, { timeoutMs: 120000 });
  const capec = {}; // CAPEC-ID -> { name, cwes:[], attack:[] }
  const cweToCapec = {}; // CWE-ID -> [CAPEC-ID]
  for (const o of data.objects ?? []) {
    if (o.type !== "attack-pattern" || o.revoked || o.x_capec_status === "Deprecated") continue;
    const id = extId(o, "capec");
    if (!id) continue;
    const refs = o.external_references ?? [];
    const cwes = refs.filter((r) => r.source_name === "cwe").map((r) => r.external_id);
    const attack = refs.filter((r) => r.source_name === "ATTACK").map((r) => (r.external_id.startsWith("T") ? r.external_id : `T${r.external_id}`));
    capec[id] = { name: o.name, cwes, attack };
    for (const c of cwes) (cweToCapec[c] ??= []).push(id);
  }
  return { url, capec, cweToCapec };
}

// ---------------------------------------------------------------- CTID Mappings Explorer
function vcmp(a, b) {
  const pa = a.split(/[.\-]/).map(Number), pb = b.split(/[.\-]/).map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  return 0;
}
const mdyToIso = (s) => { const [m, d, y] = s.split("."); return `${y}-${m}-${d}`; };

async function ghList(repo, branch, path) {
  const headers = { Accept: "application/vnd.github+json", "User-Agent": "exploited-to-control" };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const res = await fetchRetry(`https://api.github.com/repos/${repo}/contents/${path}?ref=${branch}`, { headers, retries: 1 });
  return (await res.json()).filter((e) => e.type === "dir").map((e) => e.name);
}

async function discoverCtid(cfg) {
  const { repo, branch } = cfg;
  const out = {};
  // KEV: newest ATT&CK version folder, then newest KEV snapshot inside it.
  const kevAttack = (await ghList(repo, branch, "mappings/kev")).filter((d) => d.startsWith("attack-"))
    .sort((a, b) => vcmp(b.slice(7), a.slice(7)));
  for (const a of kevAttack) {
    const snaps = (await ghList(repo, branch, `mappings/kev/${a}`)).filter((d) => /^kev-\d\d\.\d\d\.\d{4}$/.test(d))
      .sort((x, y) => mdyToIso(y.slice(4)).localeCompare(mdyToIso(x.slice(4))));
    if (snaps.length) { out.kev = `mappings/kev/${a}/${snaps[0]}/enterprise/${snaps[0]}_${a}-enterprise.json`; break; }
  }
  const nistAttack = (await ghList(repo, branch, "mappings/nist_800_53")).filter((d) => d.startsWith("attack-"))
    .sort((a, b) => vcmp(b.slice(7), a.slice(7)));
  for (const a of nistAttack) {
    const revs = await ghList(repo, branch, `mappings/nist_800_53/${a}`);
    if (revs.includes("nist_800_53-rev5")) { out.nist = `mappings/nist_800_53/${a}/nist_800_53-rev5/enterprise/nist_800_53-rev5_${a}-enterprise.json`; break; }
  }
  return out;
}

export async function loadCtid(cfg) {
  let paths = {};
  try {
    paths = await discoverCtid(cfg);
  } catch (e) {
    console.warn(`CTID discovery failed, using pinned paths: ${e.message}`);
  }
  const kevPath = paths.kev ?? cfg.kev_pinned;
  const nistPath = paths.nist ?? cfg.nist_pinned;
  const raw = (p) => `https://raw.githubusercontent.com/${cfg.repo}/${cfg.branch}/${p}`;
  const [kev, nist] = await Promise.all([fetchRetry(raw(kevPath)).then(asJson), fetchRetry(raw(nistPath)).then(asJson)]);

  const cveToAttack = {}; // CVE -> [{ id, type }]
  for (const m of kev.mapping_objects ?? []) {
    if (!m.capability_id || !m.attack_object_id || m.status === "non_mappable") continue;
    (cveToAttack[m.capability_id] ??= []).push({ id: m.attack_object_id, type: m.mapping_type, name: m.attack_object_name });
  }
  const attackToNist = {}; // T -> [control]
  const controls = {};
  for (const m of nist.mapping_objects ?? []) {
    if (m.mapping_type !== "mitigates" || !m.capability_id) continue;
    (attackToNist[m.attack_object_id] ??= []).push(m.capability_id);
    controls[m.capability_id] = m.capability_description;
  }
  return {
    kevPath, nistPath, discovered: !!paths.kev,
    kevMeta: { attackVersion: kev.metadata?.attack_version, snapshot: kev.metadata?.mapping_framework_version },
    nistMeta: { attackVersion: nist.metadata?.attack_version },
    cveToAttack, attackToNist, controls,
  };
}

// ---------------------------------------------------------------- D3FEND (cached, per technique)
function parseD3fend(json) {
  // The API returns SPARQL JSON result sets. Walk the document for any
  // results.bindings arrays and read defensive technique fields from them.
  const rows = [];
  const walk = (o) => {
    if (!o || typeof o !== "object") return;
    if (Array.isArray(o.bindings)) rows.push(...o.bindings);
    for (const v of Object.values(o)) if (v && typeof v === "object") walk(v);
  };
  walk(json);
  const val = (row, ...keys) => {
    for (const k of keys) if (row[k]?.value) return row[k].value;
    return null;
  };
  const items = new Map();
  for (const row of rows) {
    const uri = val(row, "def_tech", "def_technique");
    const label = val(row, "def_tech_label", "def_technique_label");
    if (!uri && !label) continue;
    const id = uri ? uri.split("#").pop() : label.replace(/\s+/g, "");
    if (!items.has(id)) items.set(id, { id, label: label ?? id, tactic: val(row, "def_tactic_label", "def_tactic_rel_label") });
  }
  return [...items.values()];
}

export async function loadD3fend(cfg, techniqueIds, cache) {
  const now = Date.now();
  const maxAge = cfg.cache_days * 864e5;
  let requests = 0, failures = 0;
  for (const id of techniqueIds) {
    const hit = cache[id];
    if (hit && now - Date.parse(hit.fetched) < maxAge) continue;
    if (requests >= cfg.max_requests_per_run) break;
    requests++;
    try {
      const res = await fetchRetry(cfg.api_template.replace("{id}", id), { retries: 1, timeoutMs: 30000 });
      cache[id] = { fetched: new Date().toISOString(), items: parseD3fend(await res.json()) };
    } catch (e) {
      failures++;
      // 404 means D3FEND has no entry for this technique: cache the empty answer.
      if (/HTTP 404/.test(e.message)) cache[id] = { fetched: new Date().toISOString(), items: [] };
      if (failures >= 5 && failures === requests) throw new Error(`D3FEND unreachable: ${e.message}`);
    }
    await sleep(cfg.delay_ms);
  }
  return { requests, failures };
}

// ---------------------------------------------------------------- Wikidata vendor resolution (cached)
const ORG_HINT = /(company|corporation|organi[sz]ation|software|developer|foundation|manufacturer|vendor|enterprise|business|conglomerate|project|technology)/i;

export async function loadWikidata(cfg, vendors, overrides, cache) {
  const now = Date.now();
  const maxAge = cfg.cache_days * 864e5;
  let requests = 0;
  for (const v of vendors) {
    if (v in overrides) {
      cache[v] = { qid: overrides[v], source: "override", checked: new Date().toISOString() };
      continue;
    }
    const hit = cache[v];
    if (hit && now - Date.parse(hit.checked) < maxAge) continue;
    if (requests >= cfg.max_requests_per_run) break;
    requests++;
    try {
      const url = `${cfg.api}?action=wbsearchentities&search=${encodeURIComponent(v)}&language=en&type=item&limit=5&format=json`;
      const res = await fetchRetry(url, { headers: { "User-Agent": cfg.user_agent }, retries: 1, timeoutMs: 20000 });
      const json = await res.json();
      const pick = (json.search ?? []).find((s) => ORG_HINT.test(s.description ?? ""));
      cache[v] = pick
        ? { qid: pick.id, label: pick.label, description: pick.description, source: "search", checked: new Date().toISOString() }
        : { qid: null, source: "search", checked: new Date().toISOString() };
    } catch (e) {
      if (requests === 1) throw new Error(`Wikidata unreachable: ${e.message}`);
    }
    await sleep(cfg.delay_ms);
  }
  return { requests };
}
