"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { fmtDate } from "@/lib/data";

export function Nav() {
  const path = usePathname();
  const items = [
    ["/", "Overview"],
    ["/explore/", "Explore"],
    ["/caf/", "CAF view"],
    ["/about/", "Method & data"],
  ];
  return (
    <header className="nav">
      <Link href="/" className="brand">
        <span className="brand-mark" aria-hidden>
          <svg viewBox="0 0 64 64" width="26" height="26">
            <rect width="64" height="64" rx="14" fill="var(--surface-2)" />
            <path d="M22 14 L36 32 L22 50 L8 32 Z" fill="var(--amethyst)" />
            <path d="M34 32 H54" stroke="var(--emerald)" strokeWidth="6" strokeLinecap="round" />
            <path d="M46 23 L55 32 L46 41" fill="none" stroke="var(--emerald)" strokeWidth="6" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </span>
        Exploited Vulnerabilities Dashboard
      </Link>
      <nav aria-label="Main">
        {items.map(([href, label]) => (
          <Link key={href} href={href} className={path === href || path + "/" === href ? "active" : ""}>
            {label}
          </Link>
        ))}
        <ThemeToggle />
      </nav>
    </header>
  );
}

export function ThemeToggle() {
  const [theme, setTheme] = useState("light");
  useEffect(() => setTheme(document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light"), []);
  const next = theme === "dark" ? "light" : "dark";
  const toggle = () => {
    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem("theme", next);
    } catch {}
    setTheme(next);
  };
  return (
    <button type="button" className="theme-toggle" onClick={toggle} aria-label={`Switch to ${next} theme`} title={`Switch to ${next} theme`}>
      {theme === "dark" ? (
        <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
        </svg>
      ) : (
        <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" />
        </svg>
      )}
      {theme === "dark" ? "Light" : "Dark"}
    </button>
  );
}

export function Freshness({ ds, meta }) {
  const skipped = Object.entries(meta.sources).filter(([, s]) => !s.ok).map(([k]) => k);
  return (
    <p className="fresh mono">
      KEV catalogue {meta.sources.kev.catalogVersion} · {ds.cves.length.toLocaleString()} vulnerabilities · ATT&CK v{ds.attackVersion} · built{" "}
      {fmtDate(ds.generatedAt)}
      {skipped.length > 0 && <span className="warn"> · not refreshed this run: {skipped.join(", ")}</span>}
    </p>
  );
}

export function Kpi({ label, value, note, tone = "sapphire" }) {
  return (
    <div className="kpi" style={{ "--tone": `var(--${tone})` }}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{value}</div>
      {note && <div className="kpi-note">{note}</div>}
    </div>
  );
}

/** Single-series horizontal bar list. Text stays in ink; the bar carries magnitude. */
export function BarList({ rows, label, href, tone = "sapphire", empty = "Nothing in this window.", max = 10 }) {
  const top = rows.slice(0, max);
  const peak = Math.max(1, ...top.map((r) => r.value));
  if (!top.length) return <p className="muted">{empty}</p>;
  return (
    <ul className="bars" style={{ "--tone": `var(--${tone})` }}>
      {top.map((r) => {
        const inner = (
          <>
            <span className="bar-key">
              {r.code && <span className="mono code">{r.code}</span>} {r.label}
            </span>
            <span className="bar-track" aria-hidden>
              <span className="bar-fill" style={{ width: `${(r.value / peak) * 100}%` }} />
            </span>
            <span className="bar-val mono">{r.value}</span>
          </>
        );
        return (
          <li key={r.key} title={`${r.code ? r.code + " " : ""}${r.label}: ${r.value} ${label}`}>
            {href ? <Link href={href(r)}>{inner}</Link> : <div>{inner}</div>}
          </li>
        );
      })}
    </ul>
  );
}

export function WindowPicker({ value, onChange, options }) {
  return (
    <div className="seg" role="radiogroup" aria-label="Time window">
      {options.map((o) => (
        <button key={o.days} role="radio" aria-checked={value === o.days} className={value === o.days ? "on" : ""} onClick={() => onChange(o.days)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export const SrcBadge = ({ src, rule }) =>
  src === "ctid" ? (
    <span className="badge emerald" title="Mapped by MITRE CTID (Mappings Explorer, KEV)">
      CTID
    </span>
  ) : (
    <span className="badge topaz" title={`Heuristic rule: ${rule}`}>
      heuristic
    </span>
  );

export const Loading = ({ state }) => (
  <main className="wrap">{state.error ? <p className="warn">Could not load data: {state.error}</p> : <p className="muted">Loading data…</p>}</main>
);
