"use client";
import { useState, useEffect } from "react";
import Link from "next/link";
import {
  Shield, Search, AlertTriangle, CheckCircle, ArrowRight,
  Code2, FileText, TrendingUp, Zap, Activity, Clock, ExternalLink,
} from "lucide-react";
import type { ScanResult } from "@/lib/types";

interface SessionStats {
  totalScans: number;
  totalVulns: number;
  patchesApplied: number;
  lastScanId: string | null;
}

function loadSessionStats(): SessionStats {
  if (typeof window === "undefined") return { totalScans: 0, totalVulns: 0, patchesApplied: 0, lastScanId: null };
  try {
    const raw = sessionStorage.getItem("pp_stats");
    if (raw) return JSON.parse(raw) as SessionStats;
  } catch {
    /* ignore */
  }
  return { totalScans: 0, totalVulns: 0, patchesApplied: 0, lastScanId: null };
}

const quickActions = [
  {
    title: "New Scan",
    desc: "Paste or upload Python code for instant security analysis",
    icon: Search,
    href: "/scanner",
    color: "from-cyan-500 to-cyan-600",
  },
  {
    title: "Interactive Demo",
    desc: "See PATCHPILOT scan a pre-loaded vulnerable example",
    icon: Code2,
    href: "/scanner?demo=true",
    color: "from-emerald-500 to-emerald-600",
  },
  {
    title: "GitHub Repository",
    desc: "Source code, architecture docs, and deployment guide",
    icon: FileText,
    href: "https://github.com/Swastikvitthare/PatchPilot",
    color: "from-purple-500 to-purple-600",
    external: true,
  },
];

const tips = [
  "Paste Python code or upload a .py file to scan for vulnerabilities.",
  "PATCHPILOT never executes your code — all analysis is done via AST parsing.",
  "Use the Re-scan feature to verify that patches eliminate the detected flaw.",
  "Download the security audit report to share findings with your team.",
  "Gemma 4 provides plain-language explanations and targeted remediation for each CWE.",
];

export default function DashboardPage() {
  const [stats, setStats] = useState<SessionStats>({ totalScans: 0, totalVulns: 0, patchesApplied: 0, lastScanId: null });
  const [latestScan, setLatestScan] = useState<ScanResult | null>(null);

  useEffect(() => {
    const s = loadSessionStats();
    setStats(s);

    try {
      const raw = sessionStorage.getItem("scan_latest");
      if (raw) setLatestScan(JSON.parse(raw));
    } catch {
      /* ignore */
    }
  }, []);

  const statCards = [
    { label: "Session Scans", value: stats.totalScans.toString(), icon: Search, color: "cyan" },
    { label: "Vulnerabilities Found", value: stats.totalVulns.toString(), icon: AlertTriangle, color: "orange" },
    { label: "Patches Applied", value: stats.patchesApplied.toString(), icon: CheckCircle, color: "emerald" },
    { label: "Active Engine", value: "AST + AI", icon: Activity, color: "blue" },
  ];

  return (
    <div className="min-h-screen cyber-grid">
      <div className="max-w-7xl mx-auto px-4 py-8 md:py-10">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Shield className="w-7 h-7 text-cyan-400" />
            <h1 className="text-2xl md:text-3xl font-bold text-white">Security Dashboard</h1>
          </div>
          <p className="text-gray-400 text-sm">
            Session overview. Stats reset when you close the browser tab.
          </p>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          {statCards.map((stat) => {
            const Icon = stat.icon;
            const colorClasses: Record<string, string> = {
              cyan: "text-cyan-400 bg-cyan-400/10 border-cyan-400/20",
              orange: "text-orange-400 bg-orange-400/10 border-orange-400/20",
              emerald: "text-emerald-400 bg-emerald-400/10 border-emerald-400/20",
              blue: "text-blue-400 bg-blue-400/10 border-blue-400/20",
            };
            return (
              <div key={stat.label} className="p-5 rounded-xl bg-gray-900 border border-gray-800">
                <div className={`w-9 h-9 rounded-lg border flex items-center justify-center mb-3 ${colorClasses[stat.color]}`}>
                  <Icon className="w-4.5 h-4.5" style={{ width: "18px", height: "18px" }} />
                </div>
                <div className="text-2xl md:text-3xl font-bold text-white mb-1 font-mono">{stat.value}</div>
                <div className="text-gray-400 text-sm">{stat.label}</div>
              </div>
            );
          })}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left column */}
          <div className="lg:col-span-2 space-y-6">
            {/* Quick Actions */}
            <div>
              <h2 className="text-base font-semibold text-white mb-3 flex items-center gap-2">
                <Zap className="w-4 h-4 text-cyan-400" />
                Quick Actions
              </h2>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                {quickActions.map((action) => {
                  const Icon = action.icon;
                  const inner = (
                    <>
                      <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${action.color} flex items-center justify-center mb-3 group-hover:scale-105 transition-transform shrink-0`}>
                        <Icon className="w-5 h-5 text-white" />
                      </div>
                      <div className="font-semibold text-white mb-1 text-sm flex items-center gap-1">
                        {action.title}
                        {action.external && <ExternalLink className="w-3 h-3 text-gray-500" />}
                      </div>
                      <div className="text-gray-400 text-xs leading-relaxed">{action.desc}</div>
                    </>
                  );

                  return action.external ? (
                    <a
                      key={action.title}
                      href={action.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="group p-5 rounded-xl bg-gray-900 border border-gray-800 hover:border-gray-700 transition-all block"
                    >
                      {inner}
                    </a>
                  ) : (
                    <Link
                      key={action.title}
                      href={action.href}
                      className="group p-5 rounded-xl bg-gray-900 border border-gray-800 hover:border-gray-700 transition-all block"
                    >
                      {inner}
                    </Link>
                  );
                })}
              </div>
            </div>

            {/* CTA */}
            <div className="p-5 rounded-xl bg-gradient-to-r from-cyan-950/40 to-emerald-950/40 border border-cyan-500/20">
              <div className="flex flex-col sm:flex-row sm:items-center gap-4 justify-between">
                <div>
                  <h3 className="text-white font-semibold mb-1">Ready to audit code?</h3>
                  <p className="text-gray-400 text-sm">
                    Paste Python code into the scanner and get a vulnerability report in under a second.
                  </p>
                </div>
                <Link
                  href="/scanner"
                  className="shrink-0 inline-flex items-center gap-2 px-5 py-2.5 bg-cyan-500 hover:bg-cyan-400 text-gray-950 font-bold rounded-lg transition-all text-sm whitespace-nowrap"
                >
                  Open Scanner
                  <ArrowRight className="w-4 h-4" />
                </Link>
              </div>
            </div>

            {/* Latest Scan Quick View */}
            {latestScan && (
              <div className="p-5 rounded-xl bg-gray-900 border border-gray-800">
                <h2 className="text-base font-semibold text-white mb-3 flex items-center gap-2">
                  <Clock className="w-4 h-4 text-cyan-400" />
                  Most Recent Scan
                </h2>
                <div className="flex flex-wrap items-center gap-3 mb-3">
                  <span className="font-mono text-xs text-gray-500">{latestScan.scan_id}</span>
                  <span className="text-xs text-gray-500">·</span>
                  <span className="text-xs text-gray-400">{latestScan.filename}</span>
                  <span className="text-xs text-gray-500">·</span>
                  <span className="text-xs text-gray-400">{new Date(latestScan.scanned_at).toLocaleString()}</span>
                </div>
                <div className="flex flex-wrap gap-2 mb-4">
                  {[
                    { label: "Total", val: latestScan.summary.total, cls: "text-white" },
                    { label: "Critical", val: latestScan.summary.critical, cls: "text-red-400" },
                    { label: "High", val: latestScan.summary.high, cls: "text-orange-400" },
                    { label: "Medium", val: latestScan.summary.medium, cls: "text-yellow-400" },
                    { label: "Low", val: latestScan.summary.low, cls: "text-blue-400" },
                  ].map(({ label, val, cls }) => (
                    <div key={label} className="px-3 py-1.5 rounded-lg bg-gray-800 border border-gray-700 text-center min-w-[60px]">
                      <div className={`text-lg font-bold font-mono ${cls}`}>{val}</div>
                      <div className="text-gray-500 text-[10px]">{label}</div>
                    </div>
                  ))}
                </div>
                <Link
                  href={`/results/${latestScan.scan_id}`}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-gray-700 hover:border-gray-600 text-gray-300 hover:text-white text-sm transition-all"
                >
                  View Results
                  <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            )}
          </div>

          {/* Tips Panel */}
          <div>
            <h2 className="text-base font-semibold text-white mb-3 flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-emerald-400" />
              Usage Tips
            </h2>
            <div className="p-5 rounded-xl bg-gray-900 border border-gray-800">
              <ul className="space-y-4">
                {tips.map((tip, i) => (
                  <li key={i} className="flex items-start gap-3">
                    <span className="shrink-0 w-5 h-5 rounded bg-cyan-500/15 border border-cyan-500/30 text-cyan-400 text-[10px] font-mono flex items-center justify-center mt-0.5 font-bold">
                      {i + 1}
                    </span>
                    <span className="text-gray-400 text-xs leading-relaxed">{tip}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Tech Stack */}
            <div className="mt-4 p-4 rounded-xl bg-gray-900 border border-gray-800">
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Tech Stack</h3>
              <div className="space-y-2 text-xs text-gray-500 font-mono">
                <div className="flex items-center justify-between">
                  <span>Scanning Engine</span>
                  <span className="text-cyan-400">Client AST / FastAPI</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>AI Model</span>
                  <span className="text-emerald-400">Google Gemma 4</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Frontend</span>
                  <span className="text-gray-400">Next.js 14</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Hosting</span>
                  <span className="text-gray-400">GitHub Pages</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Backend (opt.)</span>
                  <span className="text-gray-400">FastAPI / DigitalOcean</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
