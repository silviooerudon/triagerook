import type { Metadata } from "next";
import { Geist, Geist_Mono, JetBrains_Mono } from "next/font/google";
import { Analytics } from "@vercel/analytics/next";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-display",
  subsets: ["latin"],
  weight: ["400", "500", "700"],
});

export const metadata: Metadata = {
  metadataBase: new URL("https://www.triagerook.com"),
  title: {
    default: "TriageRook — Security triage for solo devs",
    template: "%s · TriageRook",
  },
  description:
    "Security triage for solo devs. Scan your GitHub repo in one click. Eleven detectors covering secrets, dependencies, supply chain, IaC, repo posture, IAM risk, and license compliance.",
  applicationName: "TriageRook",
  authors: [{ name: "Silvio Gazzoli" }],
  keywords: [
    "github security scanner",
    "secret scanning",
    "exposed secrets",
    "dependency vulnerability scanner",
    "open source security",
    "triagerook",
  ],
  openGraph: {
    type: "website",
    siteName: "TriageRook",
    title: "TriageRook — Security triage for solo devs",
    description:
      "Security triage for solo devs. Scan your GitHub repo in one click. Eleven detectors covering secrets, dependencies, supply chain, IaC, repo posture, IAM risk, and license compliance.",
    url: "/",
    locale: "en",
  },
  twitter: {
    card: "summary_large_image",
    title: "TriageRook — Security triage for solo devs",
    description:
      "Security triage for solo devs. Free, open-source scan for any public GitHub repo. Results in under a minute.",
  },
  robots: { index: true, follow: true },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} ${jetbrainsMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col bg-slate-950 text-slate-100 font-sans selection:bg-amber-400 selection:text-slate-950">
        {children}
        <Analytics />
      </body>
    </html>
  );
}
