"use client";
import { useMemo } from "react";
import { useData, inWindow, countBy } from "@/lib/data";
import { Kpi, BarList } from "@/components/ui";

/**
 * Compact widget for embedding in another dashboard with an iframe:
 *   <iframe src="https://YOUR-SITE/embed/" width="100%" height="520" title="Exploited to Control"></iframe>
 * Add ?theme=dark to match a dark host dashboard (light is the default).
 * Allowed parent sites are set in vercel.json (frame-ancestors on /embed only).
 */
export default function Embed() {
  const state = useData();
  const v = useMemo(() => {
    if (!state.ds) return null;
    const ds = state.ds;
    const c30 = inWindow(ds, 30);
    return {
      c7: inWindow(ds, 7).length,
      c30: c30.length,
      rw: c30.filter((c) => c.rw).length,
      caf: countBy(c30, (c) => c.caf).map(([k, n]) => ({ key: k, code: k, label: ds.cafOutcomes[k] ?? k, value: n })),
    };
  }, [state]);
  if (!v) return <div className="embed muted">Loading…</div>;
  const site = state.meta.siteUrl;
  return (
    <div className="embed">
      <div className="grid g3" style={{ gridTemplateColumns: "repeat(3, 1fr)" }}>
        <Kpi label="Exploited, 7 days" value={v.c7} tone="sapphire" />
        <Kpi label="Exploited, 30 days" value={v.c30} tone="amethyst" />
        <Kpi label="Ransomware use, 30 days" value={v.rw} tone="ruby" />
      </div>
      <div className="card" style={{ marginTop: 12 }}>
        <h2>CAF pressure, 30 days</h2>
        <BarList rows={v.caf} label="vulnerabilities" tone="amethyst" max={8} />
      </div>
      <p className="note" style={{ marginTop: 8 }}>
        Source: CISA KEV, MITRE CTID, ATT&CK, D3FEND. <a href={site} target="_blank" rel="noopener noreferrer">Open Exploited to Control →</a> · by{" "}
        <a href="https://www.linkedin.com/in/jonsilvester" target="_blank" rel="noopener noreferrer">Jonathan Silvester</a>
      </p>
    </div>
  );
}
