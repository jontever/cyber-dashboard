"use client";
import { cafReasons, links, pct, fmtDate } from "@/lib/data";
import { SrcBadge } from "@/components/ui";

const ext = { target: "_blank", rel: "noopener noreferrer" };

export default function CveDetail({ ds, c }) {
  if (!c) return <p className="muted">Select a vulnerability to see how it links through to controls.</p>;
  const qid = ds.vendors[c.v]?.qid;
  const caf = cafReasons(ds, c);
  const d3 = new Map();
  const nist = new Set();
  for (const t of c.t) {
    for (const d of ds.techniques[t.id]?.d3f ?? []) if (!d3.has(d.id)) d3.set(d.id, { ...d, from: t.id });
    for (const n of ds.techniques[t.id]?.nist ?? []) nist.add(n);
  }

  return (
    <article>
      <div className="mono muted" style={{ fontSize: 12 }}>{c.d} added to KEV</div>
      <h2 style={{ marginTop: 2, marginBottom: 4 }}>
        <a href={links.cve(c.id)} {...ext} className="mono">{c.id}</a>
      </h2>
      <div style={{ fontWeight: 600 }}>{c.n}</div>
      <p className="note" style={{ margin: "6px 0" }}>{c.desc}</p>
      <dl className="kv">
        <dt>Vendor</dt>
        <dd>{c.v}{qid && <> · <a href={links.wikidata(qid)} {...ext} className="mono">{qid}</a></>}</dd>
        <dt>Product</dt><dd>{c.p}</dd>
        <dt>Ransomware</dt><dd>{c.rw ? <span className="badge ruby">known use</span> : "Unknown"}</dd>
        <dt>EPSS</dt><dd className="mono">{c.e == null ? "not available" : `${pct(c.e)} (percentile ${pct(c.ep)})`}</dd>
        <dt>CISA action</dt><dd>{c.act}</dd>
      </dl>

      <ol className="chain">
        <li style={{ "--c": "var(--ruby)" }}>
          <span className="dot" />
          <div className="step">1 · Weakness</div>
          <div className="chips" style={{ marginTop: 4 }}>
            {c.cwe.length ? c.cwe.map((w) => (w.startsWith("CWE-") ? <a key={w} className="chip" href={links.cwe(w)} {...ext}>{w}</a> : <span key={w} className="chip">{w}</span>)) : <span className="muted">No CWE in KEV</span>}
          </div>
          {c.ap?.length > 0 && (
            <>
              <div className="note" style={{ marginTop: 6 }}>Related attack patterns (CAPEC, by weakness)</div>
              <div className="chips" style={{ marginTop: 2 }}>
                {c.ap.map((a) => <a key={a} className="chip" href={links.capec(a)} {...ext} title={ds.capec[a]}>{a}</a>)}
              </div>
            </>
          )}
        </li>

        <li style={{ "--c": "var(--sapphire)" }}>
          <span className="dot" />
          <div className="step">2 · ATT&CK techniques</div>
          {c.t.length === 0 && <p className="muted" style={{ margin: "4px 0" }}>Not yet mapped. CTID has no mapping and no heuristic rule matched.</p>}
          {c.t.map((t) => {
            const tech = ds.techniques[t.id];
            return (
              <div className="tech" key={t.id + (t.type ?? "")}>
                <div className="tech-head">
                  <a href={links.attack(t.id)} {...ext} className="mono">{t.id}</a>
                  <span>{tech?.name}</span>
                  <SrcBadge src={t.src} rule={t.rule} />
                  {t.type && <span className="note">{t.type.replace(/_/g, " ")}</span>}
                </div>
                <div className="note">{(tech?.tactics ?? []).map((ta) => ds.tactics[ta]?.name ?? ta).join(" · ")}</div>
              </div>
            );
          })}
        </li>

        <li style={{ "--c": "var(--emerald)" }}>
          <span className="dot" />
          <div className="step">3 · Countermeasures and controls</div>
          {d3.size > 0 ? (
            <>
              <div className="note" style={{ marginTop: 4 }}>D3FEND</div>
              <div className="chips">
                {[...d3.values()].slice(0, 24).map((d) => (
                  <a key={d.id} className="chip" href={links.d3fend(d.id)} {...ext} title={`${d.tactic ?? ""} · via ${d.from}`}>{d.label}</a>
                ))}
                {d3.size > 24 && <span className="chip">+{d3.size - 24}</span>}
              </div>
            </>
          ) : (
            <p className="note" style={{ margin: "4px 0" }}>D3FEND countermeasures appear once the D3FEND cache is populated.</p>
          )}
          {nist.size > 0 && (
            <>
              <div className="note" style={{ marginTop: 8 }}>NIST SP 800-53 r5 (CTID mappings)</div>
              <div className="chips">
                {[...nist].sort().map((n) => <span key={n} className="chip" title={ds.controls[n]}>{n}</span>)}
              </div>
            </>
          )}
        </li>

        <li style={{ "--c": "var(--amethyst)" }}>
          <span className="dot" />
          <div className="step">4 · NCSC CAF outcomes</div>
          {caf.map(({ code, reasons }) => (
            <div key={code} className="tech">
              <div className="tech-head"><span className="mono">{code}</span><span>{ds.cafOutcomes[code] ?? code}</span></div>
              <div className="note">{reasons.slice(0, 3).join("; ")}{reasons.length > 3 ? ` (+${reasons.length - 3} more)` : ""}</div>
            </div>
          ))}
        </li>
      </ol>
      <p className="note">CAF links are a heuristic starter mapping (config/caf-mapping.yaml), not NCSC guidance.</p>
    </article>
  );
}
