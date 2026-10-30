"use client";
import { useData, fmtDate } from "@/lib/data";
import { Nav, Loading } from "@/components/ui";
import Footer from "@/components/Footer";

const SOURCES = [
  ["kev", "CISA Known Exploited Vulnerabilities", "Vulnerabilities confirmed as exploited in the wild", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
  ["epss", "FIRST EPSS", "Probability of exploitation in the next 30 days", "https://www.first.org/epss/"],
  ["attack", "MITRE ATT&CK (Enterprise)", "Technique names and tactics", "https://attack.mitre.org/"],
  ["capec", "MITRE CAPEC", "Attack patterns linked to each CWE weakness", "https://capec.mitre.org/"],
  ["ctid", "MITRE CTID Mappings Explorer", "KEV → ATT&CK and NIST 800-53 → ATT&CK mappings", "https://ctid.mitre.org/projects/mappings-explorer/"],
  ["d3fend", "MITRE D3FEND", "Defensive countermeasures for each ATT&CK technique", "https://d3fend.mitre.org/"],
  ["wikidata", "Wikidata", "Vendor identities (links into the Linked Open Data Cloud)", "https://www.wikidata.org/"],
];

export default function About() {
  const state = useData();
  if (!state.ds) return (<><Nav /><Loading state={state} /></>);
  const { meta } = state;
  const cov = meta.coverage;
  const share = (n) => `${Math.round((n / cov.total) * 100)}%`;
  return (
    <>
      <Nav />
      <main className="wrap prose">
        <div className="eyebrow">Method & data</div>
        <h1>How the links are made</h1>
        <p>
          A GitHub Action runs every day. It downloads the sources below, joins them and commits static files. Vercel then redeploys the
          site. Nothing is queried when you load a page, so the site keeps working even if a source is down: it shows the last good data and
          flags anything that was not refreshed.
        </p>

        <h2 style={{ marginTop: 24 }}>The chain</h2>
        <ol>
          <li><b>KEV → CWE:</b> the weakness types CISA records for each vulnerability.</li>
          <li><b>CWE → CAPEC:</b> related attack patterns, shown as context only.</li>
          <li><b>KEV → ATT&CK:</b> MITRE CTID mappings where they exist (<b>{share(cov.directCtid)}</b>). Otherwise transparent heuristic rules
            based on the vulnerability type and product (<b>{share(cov.heuristicRules)}</b>, see <code>config/technique-rules.yaml</code>).{" "}
            <b>{share(cov.unmapped)}</b> are not yet mapped.</li>
          <li><b>ATT&CK → D3FEND and NIST 800-53:</b> countermeasures from the D3FEND API and controls from CTID's 800-53 mappings.</li>
          <li><b>→ NCSC CAF:</b> a starter mapping from ATT&CK tactics and D3FEND tactics to CAF contributing outcomes
            (<code>config/caf-mapping.yaml</code>). Every KEV entry also maps to B4.d Vulnerability management.</li>
        </ol>
        <div className="callout">
          The CAF and heuristic technique mappings are opinionated and open to review. They are not NCSC or MITRE guidance. Use them to decide
          where to look, not as assurance evidence. Corrections are welcome as pull requests.
        </div>

        <h2 style={{ marginTop: 24 }}>Sources in this build</h2>
        <div className="scroll">
          <table className="table">
            <thead><tr><th>Source</th><th>Used for</th><th>Status</th></tr></thead>
            <tbody>
              {SOURCES.map(([k, name, use, url]) => {
                const s = meta.sources[k] ?? {};
                return (
                  <tr key={k}>
                    <td><a href={url} target="_blank" rel="noopener noreferrer">{name}</a></td>
                    <td>{use}</td>
                    <td>{s.ok ? <span className="badge emerald">refreshed</span> : <span className="badge topaz" title={s.error}>not refreshed</span>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <p className="note">Built {fmtDate(meta.generatedAt)}. {cov.withEpss} of {cov.total} with EPSS; {cov.techniquesWithD3fend} of {cov.techniques} techniques with D3FEND; {cov.vendorsWithQid} of {cov.vendors} vendors linked to Wikidata.</p>

        <h2 style={{ marginTop: 24 }}>Open data</h2>
        <ul>
          <li><a href="/data/dataset.json">dataset.json</a>: everything the site uses</li>
          <li><a href="/data/graph.jsonld">graph.jsonld</a>: the same links as JSON-LD, using CVE, CWE, CAPEC, ATT&CK, D3FEND and Wikidata IRIs</li>
          <li><a href="/data/kev-enriched.csv">kev-enriched.csv</a>: one row per vulnerability</li>
          <li><a href="/data/meta.json">meta.json</a>: build time, source versions and coverage</li>
        </ul>
        <Footer />
      </main>
    </>
  );
}
