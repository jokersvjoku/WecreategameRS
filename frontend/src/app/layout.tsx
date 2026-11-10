import type { Metadata, Viewport } from "next";
import "./globals.css";
import Navbar from "@/components/layout/Navbar";
import Footer from "@/components/layout/Footer";

export const metadata: Metadata = {
  title: {
    default: "PATCHPILOT — Find the flaw. Fix the code. Prove the patch.",
    template: "%s | PATCHPILOT",
  },
  description:
    "AI-powered static security scanner for Python. Detect SQL injection, hardcoded credentials, unsafe eval, and more. Get Gemma 4 AI patches and download a verified security audit report.",
  keywords: [
    "Python security scanner",
    "static code analysis",
    "vulnerability detection",
    "SQL injection",
    "hardcoded credentials",
    "AI code patching",
    "Gemma 4",
    "CWE",
    "security audit",
    "AST analysis",
  ],
  authors: [{ name: "Swastik Vitthare" }],
  creator: "Swastik Vitthare",
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://swastikvitthare.github.io/PatchPilot/",
    siteName: "PATCHPILOT",
    title: "PATCHPILOT — Find the flaw. Fix the code. Prove the patch.",
    description:
      "Detect Python security vulnerabilities in seconds. Get AI-generated patches from Google Gemma 4 and re-scan to mathematically prove the fix works.",
  },
  twitter: {
    card: "summary_large_image",
    title: "PATCHPILOT — Python Security Scanner",
    description: "AI-powered vulnerability detection and patching for Python code.",
  },
  robots: {
    index: true,
    follow: true,
  },
  icons: {
    icon: [
      { url: "/PatchPilot/favicon.svg", type: "image/svg+xml" },
    ],
  },
};

export const viewport: Viewport = {
  themeColor: "#020817",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-gray-950 text-gray-100 flex flex-col min-h-screen antialiased font-sans overflow-x-hidden">
        <Navbar />
        <main className="flex-1 w-full min-w-0">{children}</main>
        <Footer />
      </body>
    </html>
  );
}
