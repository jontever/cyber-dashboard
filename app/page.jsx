"use client";
import { useMemo, useState } from "react";
import Link from "next/link";
import { useData, inWindow, countBy, techniquesOf, d3fendOf, nistOf, WINDOWS, fmtDate, pct } from "@/lib/data";
import { Nav, Freshness, Kpi, BarList, WindowPicker, Loading } from "@/components/ui";
import Footer from "@/components/Footer";

export default function Overview() {
  const state = useData();
  const [days, setDays] = useState(30);
  const view = useMemo(() => {
    if (!state.ds) return null;
    const { ds } = state;
    const cves = inWindow(ds, days);
    const hasEpss = ds.cves.some((c) => c.e != null);
    const hasD3 = Object.values(ds.techniques).some((t) => t.d3f.length);
    return {
      cves,
      hasEpss,
      hasD3,
      ransomware: cves.filter((c) => c.rw).length,
      highEpss: cves.filter((c) => c.e != null && c.e >= 0.5).length,
      watch: cves.filter((c) => ds.vendors[c.v]?.watch).length,
      caf: countBy(cves, (c) => c.caf).map(([k, v]) => ({ key: k, code: k, label: ds.cafOutcomes[k] ?? k, value: v })),
      techniques: countBy(cves, techniquesOf).map(([k, v]) => ({ key: k, code: k, label: ds.techniques[k]?.name ?? k, value: v })),
      counter: hasD3
        ? countBy(cves, d3fendOf(ds)).map(([k, v]) => ({ key: k, label: k, value: v }))
        : countBy(cves, nistOf(ds)).map(([k, v]) => ({ key: k, code: k, label: ds.controls[k] ?? k, value: v })),
      vendors: countBy(cves.filter((c) => ds.vendors[c.v]?.watch), (c) => [c.v]).map(([k, v]) => ({ key: k, label: k, value: v })),
      latest: [...cves].sort((a, b) => b.d.localeCompare(a.d) || (b.e ?? 0) - (a.e ?? 0)).slice(0, 12),
    };
  }, [state, days]);

  if (!view) return (<><Nav /><Loading state={state} /></>);
  const { ds, meta } = state;
  const win = WINDOWS.find((w) => w.days === days)?.label.toLowerCase();
  const q = (params) => `/explore/?${new URLSearchParams({ days: String(days), ...params })}`;

  return (
    <>
      <Nav />
      <main className="wrap">
        <div className="eyebrow">Known exploited → defended</div>
        <h1>What is being exploited, and which controls matter</h1>
        <p className="lede">
          Every vulnerability in the CISA Known Exploited Vulnerabilities catalogue, linked to the ATT&CK techniques it enables, the D3FEND
          countermeasures and NIST 800-53 controls that address them, and the NCSC CAF outcomes they sit under.
        </p>
        <Freshness ds={ds} meta={meta} />

        <div className="toolbar">
          <WindowPicker value={days} onChange={setDays} options={WINDOWS} />
          <span className="muted" style={{ fontSize: 13 }}>Added to KEV in the last {win}</span>
        </div>

        <section className="grid g4" aria-label="Headline figures">
          <Kpi label="Newly exploited" value={view.cves.length} note={`added in the last ${win}`} tone="sapphire" />
          <Kpi label="Known ransomware use" value={view.ransomware} note="per CISA KEV" tone="ruby" />
          <Kpi label="On your vendor watchlist" value={view.watch} note="edit config/vendors.yaml" tone="amethyst" />
          <Kpi
            label={view.hasEpss ? "EPSS ≥ 50%" : "Techniques involved"}
            value={view.hasEpss ? view.highEpss : view.techniques.length}
            note={view.hasEpss ? "likely to be exploited next 30 days" : "distinct ATT&CK techniques"}
            tone="emerald"
          />
        </section>

        <section className="grid g2" style={{ marginTop: 16 }}>
          <div className="card">
            <div className="card-head"><h2>CAF pressure</h2><Link href="/caf/">CAF view →</Link></div>
            <p className="note" style={{ marginTop: -6 }}>Number of newly exploited vulnerabilities touching each CAF contributing outcome.</p>
            <BarList rows={view.caf} label="vulnerabilities" tone="amethyst" max={12} href={(r) => q({ caf: r.key })} />
          </div>
          <div className="card">
            <div className="card-head"><h2>Top ATT&CK techniques</h2><Link href={q({})}>Explore →</Link></div>
            <p className="note" style={{ marginTop: -6 }}>Techniques the vulnerabilities enable, from MITRE CTID mappings or heuristic rules.</p>
            <BarList rows={view.techniques} label="vulnerabilities" tone="sapphire" max={12} href={(r) => q({ t: r.key })} />
          </div>
          <div className="card">
            <h2>{view.hasD3 ? "Countermeasures most often relevant (D3FEND)" : "Controls most often relevant (NIST 800-53 r5)"}</h2>
            <BarList rows={view.counter} label="vulnerabilities" tone="emerald" max={10} />
          </div>
          <div className="card">
            <h2>Vendor watch</h2>
            <BarList rows={view.vendors} label="vulnerabilities" tone="topaz" max={10} href={(r) => q({ v: r.key })} empty="No watchlist vendors in this window." />
          </div>
        </section>

        <section className="card" style={{ marginTop: 16 }}>
          <div className="card-head"><h2>Latest additions</h2><Link href={q({})}>All {view.cves.length} →</Link></div>
          <div className="scroll">
            <table className="table">
              <thead>
                <tr><th>Added</th><th>CVE</th><th>Vulnerability</th>{view.hasEpss && <th>EPSS</th>}<th>Techniques</th><th>CAF</th></tr>
              </thead>
              <tbody>
                {view.latest.map((c) => (
                  <tr key={c.id}>
                    <td className="nowrap mono">{c.d}</td>
                    <td className="nowrap"><Link href={`/explore/?cve=${c.id}`} className="mono">{c.id}</Link>{c.rw && <> <span className="badge ruby">ransomware</span></>}</td>
                    <td>{c.n}</td>
                    {view.hasEpss && <td className="mono">{pct(c.e)}</td>}
                    <td><div className="chips">{c.t.slice(0, 3).map((t) => <span key={t.id} className="chip">{t.id}</span>)}</div></td>
                    <td><div className="chips">{c.caf.slice(0, 4).map((k) => <span key={k} className="chip">{k}</span>)}{c.caf.length > 4 && <span className="chip">+{c.caf.length - 4}</span>}</div></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
        <Footer />
      </main>
    </>
  );
}
