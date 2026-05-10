import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
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

export const metadata: Metadata = {
  metadataBase: new URL("https://repoguard-chi.vercel.app"),
  title: {
    default: "RepoGuard — GitHub security scanner for solo devs",
    template: "%s · RepoGuard",
  },
  description:
    "Scan a public GitHub repo for exposed secrets, vulnerable dependencies, and IaC misconfigs in under 60 seconds. No CLI, no config, no sales call.",
  applicationName: "RepoGuard",
  authors: [{ name: "Silvio Gazzoli" }],
  keywords: [
    "github security scanner",
    "secret scanning",
    "exposed secrets",
    "dependency vulnerability scanner",
    "open source security",
    "repoguard",
  ],
  openGraph: {
    type: "website",
    siteName: "RepoGuard",
    title: "RepoGuard — GitHub security scanner for solo devs",
    description:
      "Scan a public GitHub repo for exposed secrets, vulnerable dependencies, and IaC misconfigs in under 60 seconds.",
    url: "/",
    locale: "en",
  },
  twitter: {
    card: "summary_large_image",
    title: "RepoGuard — GitHub security scanner for solo devs",
    description:
      "Free, open-source security scan for any public GitHub repo. Results in under a minute.",
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
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col bg-slate-950 text-slate-100 font-sans">
        {children}
        <Analytics />
      </body>
    </html>
  );
}
