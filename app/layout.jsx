import "@fontsource/space-grotesk/400.css";
import "@fontsource/space-grotesk/500.css";
import "@fontsource/space-grotesk/600.css";
import "@fontsource/space-grotesk/700.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/600.css";
import "./globals.css";

const SITE_URL =
  process.env.SITE_URL ||
  (process.env.VERCEL_PROJECT_PRODUCTION_URL ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}` : "http://localhost:3000");
const DESCRIPTION =
  "Every known exploited vulnerability (CISA KEV) linked to ATT&CK techniques, D3FEND countermeasures, NIST 800-53 controls and NCSC CAF outcomes. Open data, refreshed daily.";
const LINKEDIN = "https://www.linkedin.com/in/jonsilvester";

export const metadata = {
  metadataBase: new URL(SITE_URL),
  title: { default: "Exploited Vulnerabilities Dashboard", template: "%s · Exploited Vulnerabilities Dashboard" },
  description: DESCRIPTION,
  applicationName: "Exploited Vulnerabilities Dashboard",
  authors: [{ name: "Jonathan Silvester", url: LINKEDIN }],
  creator: "Jonathan Silvester",
  keywords: ["CISA KEV", "MITRE ATT&CK", "D3FEND", "NIST 800-53", "NCSC CAF", "EPSS", "vulnerability management", "linked open data"],
  openGraph: {
    type: "website",
    siteName: "Exploited Vulnerabilities Dashboard",
    title: "Exploited Vulnerabilities Dashboard",
    description: DESCRIPTION,
    url: "/",
    locale: "en_GB",
  },
  alternates: {
    types: {
      "application/rss+xml": [
        { url: "/feed.xml", title: "Newly exploited vulnerabilities" },
        { url: "/feed-ransomware.xml", title: "Known ransomware use" },
        { url: "/feed-watchlist.xml", title: "Vendor watchlist" },
      ],
    },
  },
  twitter: { card: "summary_large_image", title: "Exploited Vulnerabilities Dashboard", description: DESCRIPTION },
};

export const viewport = {
  themeColor: "#f6f7fb",
};

// Applies the saved theme before first paint so there is no flash of the wrong theme.
// Light is the default. A ?theme=dark|light URL parameter (used by the embed) wins over the saved choice.
const THEME_SCRIPT = `(function(){try{var p=new URLSearchParams(location.search).get("theme");
var t=(p==="dark"||p==="light")?p:localStorage.getItem("theme");
if(t==="dark")document.documentElement.setAttribute("data-theme","dark");}catch(e){}})();`;

export default function RootLayout({ children }) {
  return (
    <html lang="en-GB" data-theme="light" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
