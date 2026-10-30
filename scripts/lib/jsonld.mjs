/**
 * Express the dataset as JSON-LD so it can be linked to the wider web of data.
 * CVE, CWE, CAPEC, ATT&CK and Wikidata nodes use their canonical public IRIs;
 * properties that have no shared vocabulary use this project's own namespace.
 */
const cveIri = (id) => `https://www.cve.org/CVERecord?id=${id}`;
const cweIri = (id) => `https://cwe.mitre.org/data/definitions/${id.replace(/^CWE-/, "")}.html`;
const capecIri = (id) => `https://capec.mitre.org/data/definitions/${id.replace(/^CAPEC-/, "")}.html`;
const attackIri = (id) => `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
const d3fIri = (id) => `http://d3fend.mitre.org/ontologies/d3fend.owl#${id}`;
const wdIri = (q) => `http://www.wikidata.org/entity/${q}`;

export function toJsonLd(ds, siteUrl) {
  const cafIri = (code) => `${siteUrl}/caf#${code}`;
  const nistIri = (id) => `${siteUrl}/nist-800-53#${id}`;
  const graph = [];

  for (const c of ds.cves) {
    const node = {
      "@id": cveIri(c.id),
      "@type": "e2c:ExploitedVulnerability",
      "schema:identifier": c.id,
      "schema:name": c.n,
      "e2c:dateAddedToKev": { "@value": c.d, "@type": "xsd:date" },
      "e2c:knownRansomwareUse": c.rw,
      "e2c:weakness": c.cwe.filter((w) => w.startsWith("CWE-")).map((w) => ({ "@id": cweIri(w) })),
      "e2c:enablesTechnique": c.t.map((t) => ({ "@id": attackIri(t.id) })),
      "e2c:cafOutcome": c.caf.map((k) => ({ "@id": cafIri(k) })),
    };
    if (c.e != null) node["e2c:epss"] = c.e;
    const qid = ds.vendors[c.v]?.qid;
    node["e2c:vendor"] = qid ? { "@id": wdIri(qid), "schema:name": c.v } : { "schema:name": c.v };
    // Provenance: which techniques come from MITRE CTID and which from heuristic rules.
    node["e2c:techniqueMapping"] = c.t.map((t) => ({
      "e2c:technique": { "@id": attackIri(t.id) },
      "e2c:source": t.src === "ctid" ? "MITRE CTID KEV mapping" : `Heuristic rule: ${t.rule}`,
      ...(t.type ? { "e2c:mappingType": t.type } : {}),
    }));
    node["e2c:relatedAttackPattern"] = (c.ap ?? []).map((a) => ({ "@id": capecIri(a) }));
    graph.push(node);
  }

  for (const [id, t] of Object.entries(ds.techniques)) {
    graph.push({
      "@id": attackIri(id),
      "@type": "e2c:AttackTechnique",
      "schema:identifier": id,
      "schema:name": t.name,
      "e2c:tactic": t.tactics,
      "e2c:countermeasure": t.d3f.map((d) => ({ "@id": d3fIri(d.id), "schema:name": d.label, "e2c:d3fendTactic": d.tactic })),
      "e2c:mitigatedByControl": t.nist.map((n) => ({ "@id": nistIri(n), "schema:name": ds.controls[n] })),
    });
  }

  for (const [code, name] of Object.entries(ds.cafOutcomes)) {
    graph.push({ "@id": cafIri(code), "@type": "e2c:CafContributingOutcome", "schema:identifier": code, "schema:name": name });
  }

  return {
    "@context": {
      schema: "https://schema.org/",
      xsd: "http://www.w3.org/2001/XMLSchema#",
      e2c: `${siteUrl}/vocab#`,
    },
    "@id": `${siteUrl}/data/graph.jsonld`,
    "schema:dateModified": ds.generatedAt,
    "schema:license": "https://opensource.org/licenses/MIT",
    "@graph": graph,
  };
}
