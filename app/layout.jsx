import "@fontsource/space-grotesk/400.css";
import "@fontsource/space-grotesk/500.css";
import "@fontsource/space-grotesk/600.css";
import "@fontsource/space-grotesk/700.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/600.css";
import "./globals.css";

const SITE_URL =
  process.env.SITE_URL ??
  (process.env.VERCEL_PROJECT_PRODUCTION_URL ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}` : "http://localhost:3000");
const DESCRIPTION =
  "Every known exploited vulnerability (CISA KEV) linked to ATT&CK techniques, D3FEND countermeasures, NIST 800-53 controls and NCSC CAF outcomes. Open data, refreshed daily.";
const LINKEDIN = "https://www.linkedin.com/in/jonsilvester";

export const metadata = {
  metadataBase: new URL(SITE_URL),
  title: { default: "Exploited → Control", template: "%s · Exploited → Control" },
  description: DESCRIPTION,
  applicationName: "Exploited → Control",
  authors: [{ name: "Jonathan Silvester", url: LINKEDIN }],
  creator: "Jonathan Silvester",
  keywords: ["CISA KEV", "MITRE ATT&CK", "D3FEND", "NIST 800-53", "NCSC CAF", "EPSS", "vulnerability management", "linked open data"],
  openGraph: {
    type: "website",
    siteName: "Exploited → Control",
    title: "Exploited → Control",
    description: DESCRIPTION,
    url: "/",
    locale: "en_GB",
  },
  twitter: { card: "summary_large_image", title: "Exploited → Control", description: DESCRIPTION },
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
