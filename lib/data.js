"use client";
import { useEffect, useState } from "react";

let cache = null;
let pending = null;

/** Load dataset.json and meta.json once per page load. */
export function useData() {
  const [state, setState] = useState(cache ?? { loading: true });
  useEffect(() => {
    if (cache) return;
    pending ??= Promise.all([
      fetch("/data/dataset.json").then((r) => r.json()),
      fetch("/data/meta.json").then((r) => r.json()),
    ])
      .then(([ds, meta]) => (cache = { ds, meta }))
      .catch((error) => ({ error: String(error) }));
    pending.then(setState);
  }, []);
  return state;
}

export const WINDOWS = [
  { days: 7, label: "7 days" },
  { days: 30, label: "30 days" },
  { days: 90, label: "90 days" },
  { days: 365, label: "12 months" },
  { days: 0, label: "All time" },
];

/** CVEs added to KEV within `days` of the dataset build date (0 = all). */
export function inWindow(ds, days) {
  if (!days) return ds.cves;
  const ref = new Date(ds.generatedAt);
  ref.setUTCDate(ref.getUTCDate() - days);
  const cutoff = ref.toISOString().slice(0, 10);
  return ds.cves.filter((c) => c.d >= cutoff);
}

export function countBy(items, keysOf) {
  const m = new Map();
  for (const it of items) for (const k of new Set(keysOf(it))) m.set(k, (m.get(k) ?? 0) + 1);
  return [...m.entries()].sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])));
}

export const techniquesOf = (c) => c.t.map((t) => t.id);
export const d3fendOf = (ds) => (c) => c.t.flatMap((t) => (ds.techniques[t.id]?.d3f ?? []).map((d) => d.label));
export const nistOf = (ds) => (c) => c.t.flatMap((t) => ds.techniques[t.id]?.nist ?? []);

/** Explain why a CVE maps to each CAF outcome. */
export function cafReasons(ds, c) {
  const why = {};
  const add = (code, reason) => (why[code] ??= new Set()).add(reason);
  for (const code of ds.cafMapping.always ?? []) add(code, "Every KEV entry is a known exploited vulnerability");
  for (const t of c.t) {
    const tech = ds.techniques[t.id];
    for (const ta of tech?.tactics ?? []) {
      for (const code of ds.cafMapping.attack_tactics[ta] ?? []) add(code, `${t.id} is in the ATT&CK tactic ${ds.tactics[ta]?.name ?? ta}`);
    }
    for (const d of tech?.d3f ?? []) {
      for (const code of ds.cafMapping.d3fend_tactics[d.tactic] ?? []) add(code, `D3FEND ${d.tactic}: ${d.label}`);
    }
  }
  return Object.entries(why).sort(([a], [b]) => a.localeCompare(b)).map(([code, set]) => ({ code, reasons: [...set] }));
}

export const fmtDate = (iso) =>
  new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });

export const pct = (x) => (x == null ? "–" : `${(x * 100).toFixed(x < 0.1 ? 1 : 0)}%`);

export const links = {
  cve: (id) => `https://www.cve.org/CVERecord?id=${id}`,
  cwe: (id) => `https://cwe.mitre.org/data/definitions/${id.replace("CWE-", "")}.html`,
  capec: (id) => `https://capec.mitre.org/data/definitions/${id.replace("CAPEC-", "")}.html`,
  attack: (id) => `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`,
  d3fend: (id) => `https://d3fend.mitre.org/technique/d3f:${id}/`,
  wikidata: (q) => `https://www.wikidata.org/wiki/${q}`,
};
