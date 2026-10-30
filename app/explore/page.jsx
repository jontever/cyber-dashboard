"use client";
import { Suspense, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useData, inWindow, WINDOWS, pct } from "@/lib/data";
import { Nav, Freshness, Loading } from "@/components/ui";
import CveDetail from "@/components/CveDetail";
import Footer from "@/components/Footer";

const PAGE = 40;

function Explorer() {
  const state = useData();
  const params = useSearchParams();
  const router = useRouter();
  const [f, setF] = useState(() => ({
    q: params.get("q") ?? "",
    days: Number(params.get("days") ?? 0),
    v: params.get("v") ?? "",
    caf: params.get("caf") ?? "",
    t: params.get("t") ?? "",
    src: params.get("src") ?? "",
    rw: params.get("rw") === "1",
    watch: params.get("watch") === "1",
  }));
  const [sel, setSel] = useState(params.get("cve") ?? null);
  const [page, setPage] = useState(0);
  const set = (k) => (e) => { setPage(0); setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value }); };

  // Keep the URL in step so views can be shared.
  useEffect(() => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(f)) if (v && v !== "0") p.set(k, v === true ? "1" : String(v));
    if (sel) p.set("cve", sel);
    router.replace(`/explore/?${p}`, { scroll: false });
  }, [f, sel, router]);

  const ds = state.ds;
  const rows = useMemo(() => {
    if (!ds) return [];
    const q = f.q.trim().toLowerCase();
    return inWindow(ds, Number(f.days)).filter((c) =>
      (!q || `${c.id} ${c.v} ${c.p} ${c.n}`.toLowerCase().includes(q)) &&
      (!f.v || c.v === f.v) &&
      (!f.caf || c.caf.includes(f.caf)) &&
      (!f.t || c.t.some((t) => t.id === f.t)) &&
      (!f.src || (f.src === "none" ? c.t.length === 0 : c.t.some((t) => t.src === f.src))) &&
      (!f.rw || c.rw) &&
      (!f.watch || ds.vendors[c.v]?.watch));
  }, [ds, f]);

  if (!ds) return <Loading state={state} />;
  const vendors = Object.keys(ds.vendors).sort((a, b) => a.localeCompare(b));
  const techs = Object.entries(ds.techniques).sort(([a], [b]) => a.localeCompare(b));
  const selected = ds.cves.find((c) => c.id === sel);
  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  const hasEpss = ds.cves.some((c) => c.e != null);

  return (
    <main className="wrap">
      <h1>Explore</h1>
      <Freshness ds={ds} meta={state.meta} />
      <div className="filters">
        <label>Search<input type="search" value={f.q} onChange={set("q")} placeholder="CVE, vendor, product…" /></label>
        <label>Added
          <select value={f.days} onChange={set("days")}>{WINDOWS.map((w) => <option key={w.days} value={w.days}>{w.label}</option>)}</select>
        </label>
        <label>Vendor
          <select value={f.v} onChange={set("v")}><option value="">All vendors</option>{vendors.map((v) => <option key={v}>{v}</option>)}</select>
        </label>
        <label>CAF outcome
          <select value={f.caf} onChange={set("caf")}><option value="">Any</option>{Object.entries(ds.cafOutcomes).map(([k, n]) => <option key={k} value={k}>{k} {n}</option>)}</select>
        </label>
        <label>Technique
          <select value={f.t} onChange={set("t")}><option value="">Any</option>{techs.map(([k, t]) => <option key={k} value={k}>{k} {t.name}</option>)}</select>
        </label>
        <label>Mapping
          <select value={f.src} onChange={set("src")}>
            <option value="">Any</option><option value="ctid">MITRE CTID</option><option value="rule">Heuristic</option><option value="none">Unmapped</option>
          </select>
        </label>
        <label className="check"><input type="checkbox" checked={f.rw} onChange={set("rw")} /> Ransomware</label>
        <label className="check"><input type="checkbox" checked={f.watch} onChange={set("watch")} /> Watchlist</label>
      </div>

      <div className="split">
        <section className="card" aria-label="Results">
          <div className="card-head">
            <h2>{rows.length.toLocaleString()} vulnerabilities</h2>
            <a href="/data/kev-enriched.csv" download>Download CSV</a>
          </div>
          <div className="scroll">
            <table className="table">
              <thead><tr><th>Added</th><th>CVE</th><th>Vulnerability</th>{hasEpss && <th>EPSS</th>}<th>Mapping</th></tr></thead>
              <tbody>
                {rows.slice(page * PAGE, page * PAGE + PAGE).map((c) => (
                  <tr key={c.id} className={`row ${sel === c.id ? "sel" : ""}`} tabIndex={0} onClick={() => setSel(c.id)}
                    onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), setSel(c.id))} aria-selected={sel === c.id}>
                    <td className="nowrap mono">{c.d}</td>
                    <td className="nowrap mono">{c.id}{c.rw && <><br /><span className="badge ruby">ransomware</span></>}</td>
                    <td>{c.n}</td>
                    {hasEpss && <td className="mono">{pct(c.e)}</td>}
                    <td>{c.t.length === 0 ? <span className="badge muted">none</span> : c.t[0].src === "ctid" ? <span className="badge emerald">CTID</span> : <span className="badge topaz">heuristic</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pager">
            <button className="btn" disabled={page === 0} onClick={() => setPage(page - 1)}>← Prev</button>
            <span>Page {page + 1} of {pages}</span>
            <button className="btn" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>Next →</button>
          </div>
        </section>
        <aside className="card detail" aria-label="Selected vulnerability">
          <CveDetail ds={ds} c={selected} />
        </aside>
      </div>
      <Footer />
    </main>
  );
}

export default function ExplorePage() {
  return (
    <>
      <Nav />
      <Suspense fallback={<main className="wrap"><p className="muted">Loading…</p></main>}>
        <Explorer />
      </Suspense>
    </>
  );
}
