import Link from "next/link";
import { Nav } from "@/components/ui";
import Footer from "@/components/Footer";

export const metadata = { title: "How to use" };

const ROLES = [
  {
    who: "Vulnerability management",
    tone: "ruby",
    goal: "Weekly triage of newly exploited vulnerabilities",
    steps: [
      <>Open <Link href="/explore/?days=7&watch=1">Explore with the last 7 days and your watchlist</Link>.</>,
      <>Tick <b>Ransomware</b> to see the most urgent first, then untick it to review the rest.</>,
      <>Check the <b>EPSS</b> column: a higher score means exploitation is more likely in the next 30 days, so deal with those first.</>,
      <>Open each vulnerability, read <b>CISA action</b>, and check the vendor advisory before raising a ticket.</>,
      <>Use <b>Download CSV</b> to drop the list into your tracker.</>,
    ],
  },
  {
    who: "CAF assessors and assurance leads",
    tone: "amethyst",
    goal: "Decide which CAF outcomes to re-check",
    steps: [
      <>Open the <Link href="/caf/">CAF view</Link> and set the window to <b>90 days</b>.</>,
      <>Outcomes at the top are under the most exploitation pressure. Start there.</>,
      <>Use each outcome's top techniques and countermeasures as prompts: are those controls in place and evidenced?</>,
      <>Click <b>See vulnerabilities</b> to get the specific CVEs to cite in your assessment notes.</>,
    ],
  },
  {
    who: "Security architects and design reviewers",
    tone: "sapphire",
    goal: "Check that designs and patterns defend against what is being exploited",
    steps: [
      <>On the <Link href="/">Overview</Link>, read <b>Top ATT&CK techniques</b> for the last 30 or 90 days.</>,
      <>Click a technique, for example <Link href="/explore/?days=90&t=T1190">T1190 Exploit Public-Facing Application</Link>.</>,
      <>Open any vulnerability and read step 3 of its chain: the D3FEND countermeasures and NIST 800-53 controls.</>,
      <>Compare those against your control patterns and the design in front of you.</>,
    ],
  },
  {
    who: "SOC and detection engineers",
    tone: "teal",
    goal: "Prioritise detections for active techniques",
    steps: [
      <>Filter <Link href="/explore/?days=30">Explore</Link> to the last 30 days and pick a technique.</>,
      <>In each vulnerability's chain, look for D3FEND countermeasures under the <b>Detect</b> tactic.</>,
      <>Check whether you have detection content for those techniques; prioritise those with ransomware use.</>,
    ],
  },
  {
    who: "CISOs and senior managers",
    tone: "emerald",
    goal: "A one-page view for briefings",
    steps: [
      <>Use the <Link href="/">Overview</Link> with a 30-day window: headline counts, CAF pressure and vendor watch.</>,
      <>Share the page link: the window and filters you choose are kept in the URL on the Explore page.</>,
      <>Or embed the compact widget in another dashboard (see below).</>,
    ],
  },
];

const FILTERS = [
  ["Search", "Matches CVE ID, vendor, product or vulnerability name."],
  ["Added", "When CISA added the vulnerability to the KEV catalogue (7 days to all time)."],
  ["Vendor", "One vendor, as named in the KEV catalogue."],
  ["CAF outcome", "Vulnerabilities linked to a specific NCSC CAF contributing outcome."],
  ["Technique", "Vulnerabilities linked to a specific MITRE ATT&CK technique."],
  ["Mapping", "MITRE CTID (curated), heuristic (rule-based), or unmapped."],
  ["Ransomware", "Only vulnerabilities CISA records as used in ransomware campaigns."],
  ["Watchlist", "Only vendors on the watchlist, which reflects common UK public-sector products."],
];

const TERMS = [
  ["KEV", "CISA's Known Exploited Vulnerabilities catalogue: vulnerabilities confirmed as exploited in the wild."],
  ["EPSS", "Exploit Prediction Scoring System (FIRST): the probability of exploitation in the next 30 days."],
  ["ATT&CK", "MITRE's catalogue of attacker tactics and techniques, such as T1190."],
  ["D3FEND", "MITRE's catalogue of defensive countermeasures, grouped by tactic (Harden, Detect, Isolate and others)."],
  ["NIST 800-53", "The US control catalogue. Links come from MITRE CTID's published mappings."],
  ["CAF", "The NCSC Cyber Assessment Framework. Links here are a heuristic starter mapping, not NCSC guidance."],
  ["CTID", "Mapping curated by MITRE's Center for Threat-Informed Defense. The most reliable source here."],
  ["Heuristic", "Mapping produced by transparent rules from the vulnerability type and product. Treat as indicative."],
];

export default function HowTo() {
  return (
    <>
      <Nav />
      <main className="wrap">
        <div className="eyebrow">How to use</div>
        <h1>Getting value from the dashboard</h1>
        <p className="lede">
          The dashboard answers two questions: <b>what is being exploited</b>, and <b>which countermeasures, controls and CAF outcomes
          matter as a result</b>. Start with the quick start, then use the workflow for your role.
        </p>

        <section className="card howto-quick" style={{ marginTop: 20 }}>
          <h2>Quick start</h2>
          <ol className="howto-steps">
            <li><b>Pick a time window</b> on the <Link href="/">Overview</Link>: 7 days for this week's news, 90 days for trends.</li>
            <li><b>Read the panels.</b> CAF pressure shows where exploitation lands in the CAF. Top techniques shows how attackers are getting in.</li>
            <li><b>Click any bar</b> to open <Link href="/explore/">Explore</Link> with that filter applied.</li>
            <li><b>Click a vulnerability</b> to see its full chain, from weakness through technique and countermeasure to CAF outcome.</li>
          </ol>
        </section>

        <section className="card" style={{ marginTop: 16 }}>
          <h2>Reading a vulnerability's chain</h2>
          <p className="note" style={{ marginTop: -6 }}>Every vulnerability on the Explore page opens a four-step chain.</p>
          <div className="grid g4 howto-chain">
            <div style={{ "--c": "var(--ruby)" }}><span className="step mono">1 · Weakness</span><p>The CWE weakness type, and related CAPEC attack patterns for context.</p></div>
            <div style={{ "--c": "var(--sapphire)" }}><span className="step mono">2 · Techniques</span><p>The ATT&CK techniques the vulnerability enables. A <span className="badge emerald">CTID</span> badge means curated; <span className="badge topaz">heuristic</span> means rule-based.</p></div>
            <div style={{ "--c": "var(--emerald)" }}><span className="step mono">3 · Countermeasures</span><p>D3FEND countermeasures and NIST 800-53 controls that address those techniques.</p></div>
            <div style={{ "--c": "var(--amethyst)" }}><span className="step mono">4 · CAF outcomes</span><p>The NCSC CAF contributing outcomes involved, each with the reason it was linked.</p></div>
          </div>
        </section>

        <h2 style={{ marginTop: 28 }}>Workflows by role</h2>
        <section className="grid g2">
          {ROLES.map((r) => (
            <div key={r.who} className="card" style={{ borderTop: `3px solid var(--${r.tone})` }}>
              <h3 style={{ marginTop: 0, fontSize: 16 }}>{r.who}</h3>
              <p className="note" style={{ marginTop: -2 }}>{r.goal}</p>
              <ol className="howto-steps">{r.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
            </div>
          ))}
        </section>

        <section className="grid g2" style={{ marginTop: 16 }}>
          <div className="card">
            <h2>Explore filters</h2>
            <table className="table">
              <tbody>{FILTERS.map(([k, v]) => <tr key={k}><td className="nowrap"><b>{k}</b></td><td>{v}</td></tr>)}</tbody>
            </table>
          </div>
          <div className="card">
            <h2>Key terms</h2>
            <table className="table">
              <tbody>{TERMS.map(([k, v]) => <tr key={k}><td className="nowrap"><b>{k}</b></td><td>{v}</td></tr>)}</tbody>
            </table>
          </div>
        </section>

        <section className="grid g2" style={{ marginTop: 16 }}>
          <div className="card">
            <h2>Share, export and reuse</h2>
            <ul className="howto-list">
              <li><b>Share a view:</b> filters on the Explore page are kept in the URL, so you can copy and send it.</li>
              <li><b>Spreadsheet:</b> <a href="/data/kev-enriched.csv" download>kev-enriched.csv</a> has one row per vulnerability.</li>
              <li><b>Open data:</b> <a href="/data/dataset.json">dataset.json</a> and linked data in <a href="/data/graph.jsonld">graph.jsonld</a>.</li>
              <li><b>Embed</b> the compact widget in another dashboard. Add <code>?theme=dark</code> for dark backgrounds:</li>
            </ul>
            <pre className="howto-code">{`<iframe src="https://www.cyberteam.uk/embed/"
  width="100%" height="520" style="border:0"
  title="Exploited Vulnerabilities Dashboard"></iframe>`}</pre>
          </div>
          <div className="card">
            <h2>Use it well</h2>
            <ul className="howto-list">
              <li><b>It does not know your estate.</b> Use it to prioritise, and confirm exposure with your own asset inventory and scanners.</li>
              <li><b>Check the vendor advisory</b> before acting. This is a prioritisation aid, not threat intelligence.</li>
              <li><b>Treat heuristic and CAF mappings as indicative.</b> CTID mappings are curated; the others are reasoned but unofficial.</li>
              <li><b>KEV is a US catalogue.</b> Also watch NCSC advisories for UK-specific exploitation.</li>
              <li><b>Data refreshes twice a day</b> (06:23 and 19:23 UTC). The build date is shown under each page heading.</li>
              <li>See <Link href="/about/">Method & data</Link> for how every link is made and which sources refreshed.</li>
            </ul>
          </div>
        </section>
        <Footer />
      </main>
    </>
  );
}
