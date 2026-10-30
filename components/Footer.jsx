const LINKEDIN = "https://www.linkedin.com/in/jonsilvester";
const REPO = "https://github.com/jontever/cyber-dashboard";

export default function Footer() {
  return (
    <footer className="site">
      <div className="footer-row">
        <span>
          Built by{" "}
          <a href={LINKEDIN} target="_blank" rel="me noopener noreferrer" className="linkedin">
            <svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true">
              <path fill="currentColor" d="M20.45 20.45h-3.56v-5.57c0-1.33-.02-3.04-1.85-3.04-1.86 0-2.14 1.45-2.14 2.94v5.67H9.34V9h3.42v1.56h.05c.48-.9 1.64-1.85 3.37-1.85 3.6 0 4.27 2.37 4.27 5.46v6.28zM5.34 7.43a2.07 2.07 0 1 1 0-4.13 2.07 2.07 0 0 1 0 4.13zM7.12 20.45H3.56V9h3.56v11.45zM22.22 0H1.77C.79 0 0 .77 0 1.73v20.54C0 23.23.79 24 1.77 24h20.45c.98 0 1.78-.77 1.78-1.73V1.73C24 .77 23.2 0 22.22 0z" />
            </svg>
            Jonathan Silvester
          </a>
        </span>
        <a href={REPO} target="_blank" rel="noopener noreferrer">Source on GitHub</a>
      </div>
      <p>
        Open source (MIT). Data: CISA KEV, FIRST EPSS, MITRE ATT&CK, CAPEC, D3FEND and CTID Mappings Explorer, and Wikidata, each under its own
        terms. CAF mappings are heuristic and not endorsed by NCSC. This is not threat intelligence: check vendor advisories before acting.
      </p>
    </footer>
  );
}
