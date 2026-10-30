"use client";
import { useMemo, useState } from "react";
import Link from "next/link";
import { useData, inWindow, countBy, techniquesOf, d3fendOf, nistOf, WINDOWS } from "@/lib/data";
import { Nav, Freshness, WindowPicker, Loading } from "@/components/ui";
import Footer from "@/components/Footer";

export default function CafPage() {
  const state = useData();
  const [days, setDays] = useState(90);
  const groups = useMemo(() => {
    if (!state.ds) return null;
    const ds = state.ds;
    const cves = inWindow(ds, days);
    const hasD3 = Object.values(ds.techniques).some((t) => t.d3f.length);
    return Object.entries(ds.cafOutcomes)
      .map(([code, name]) => {
        const hit = cves.filter((c) => c.caf.includes(code));
        return {
          code, name, count: hit.length, ransomware: hit.filter((c) => c.rw).length,
          techniques: countBy(hit, techniquesOf).slice(0, 4),
          counter: (hasD3 ? countBy(hit, d3fendOf(ds)) : countBy(hit, nistOf(ds))).slice(0, 6),
          hasD3,
        };
      })
      .sort((a, b) => b.count - a.count || a.code.localeCompare(b.code));
  }, [state, days]);

  if (!groups) return (<><Nav /><Loading state={state} /></>);
  const { ds, meta } = state;
  const peak = Math.max(1, ...groups.map((g) => g.count));
  return (
    <>
      <Nav />
      <main className="wrap">
        <div className="eyebrow">NCSC Cyber Assessment Framework</div>
        <h1>Where exploitation pressure lands in the CAF</h1>
        <p className="lede">
          Each newly exploited vulnerability is linked to CAF contributing outcomes through its ATT&CK tactics and D3FEND countermeasures. Use this
          to decide which outcomes to re-check first. The mapping is a reviewable starter set in <code>config/caf-mapping.yaml</code>.
        </p>
        <Freshness ds={ds} meta={meta} />
        <div className="toolbar"><WindowPicker value={days} onChange={setDays} options={WINDOWS} /></div>
        <section className="grid g3">
          {groups.map((g) => (
            <div className="card" key={g.code} style={{ borderTop: "3px solid var(--amethyst)" }}>
              <div className="card-head">
                <h2 style={{ marginBottom: 2 }}><span className="mono muted" style={{ fontSize: 13 }}>{g.code}</span> {g.name}</h2>
              </div>
              <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
                <span style={{ fontSize: 30, fontWeight: 600 }}>{g.count}</span>
                <span className="note">vulnerabilities{g.ransomware ? ` · ${g.ransomware} with ransomware use` : ""}</span>
              </div>
              <div className="bar-track" style={{ margin: "6px 0 10px" }} aria-hidden>
                <span className="bar-fill" style={{ width: `${(g.count / peak) * 100}%`, background: "var(--amethyst)" }} />
              </div>
              {g.techniques.length > 0 && (
                <>
                  <div className="note">Top techniques</div>
                  <div className="chips" style={{ marginBottom: 8 }}>
                    {g.techniques.map(([t, n]) => <Link key={t} className="chip" href={`/explore/?days=${days}&caf=${g.code}&t=${t}`} title={ds.techniques[t]?.name}>{t} · {n}</Link>)}
                  </div>
                  <div className="note">{g.hasD3 ? "Most relevant D3FEND countermeasures" : "Most relevant NIST 800-53 controls"}</div>
                  <div className="chips">
                    {g.counter.map(([k, n]) => <span key={k} className="chip" title={ds.controls[k] ?? k}>{k} · {n}</span>)}
                  </div>
                </>
              )}
              <p style={{ marginBottom: 0 }}><Link href={`/explore/?days=${days}&caf=${g.code}`} className="note">See vulnerabilities →</Link></p>
            </div>
          ))}
        </section>
        <Footer />
      </main>
    </>
  );
}
