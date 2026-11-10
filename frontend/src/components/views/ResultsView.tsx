"use client";
import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  Shield, AlertTriangle, ChevronLeft, Download, Wrench,
  CheckCircle, XCircle, Info, Loader2, Sparkles,
} from "lucide-react";
import { ScanResult, Vulnerability } from "@/lib/types";
import VulnerabilityCard from "@/components/results/VulnerabilityCard";
import { generateReport } from "@/lib/api";
import { clientScan } from "@/lib/client-scanner";

type SeverityFilter = "all" | "critical" | "high" | "medium" | "low" | "info";

const DEMO_CODE = `"""
PATCHPILOT Demo — Intentionally Vulnerable Python
"""
import pickle
import os
import random

# Hardcoded credentials
DB_PASSWORD = "admin123!supersecret"
API_KEY = "AKIAIOSFODNN7EXAMPLE"

def get_user(username):
    # SQL Injection via f-string
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

def run_command(cmd):
    # OS command injection
    os.system("backup_service " + cmd)

def parse_expression(expr):
    # Dangerous eval()
    return eval(expr)

def load_session(data: bytes):
    # Insecure pickle deserialization
    return pickle.loads(data)

from flask import Flask
app = Flask(__name__)
app.run(debug=True, host="0.0.0.0")
`;

export default function ResultsView() {
  const params = useParams();
  const router = useRouter();
  const scanId = (params?.id as string) || "latest";

  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [filter, setFilter] = useState<SeverityFilter>("all");
  const [isDownloading, setIsDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const stored = sessionStorage.getItem(`scan_${scanId}`) || sessionStorage.getItem("scan_latest");
    if (stored) {
      setScanResult(JSON.parse(stored));
    } else {
      // Auto-populate with demo scan so static pages NEVER 404 or show empty state
      const demoResult = clientScan(DEMO_CODE, "python", "vulnerable_demo.py");
      setScanResult(demoResult);
      try {
        sessionStorage.setItem(`scan_${scanId}`, JSON.stringify(demoResult));
        sessionStorage.setItem(`code_${scanId}`, DEMO_CODE);
      } catch {
        /* ignore */
      }
    }
  }, [scanId]);

  const filtered: Vulnerability[] = scanResult
    ? filter === "all"
      ? scanResult.vulnerabilities
      : scanResult.vulnerabilities.filter((v) => v.severity === filter)
    : [];

  const handleGenerateAllPatches = () => {
    if (!scanResult) return;
    router.push(`/patch/${scanId}`);
  };

  const handleDownloadReport = async () => {
    if (!scanResult) return;
    setIsDownloading(true);
    try {
      const code = sessionStorage.getItem(`code_${scanId}`) || DEMO_CODE;
      const blob = await generateReport({
        scan_id: scanId,
        original_code: code,
        vulnerabilities: scanResult.vulnerabilities,
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `patchpilot-report-${scanId.slice(0, 8)}.txt`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setError("Failed to generate report.");
    } finally {
      setIsDownloading(false);
    }
  };

  if (!scanResult) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  const { summary } = scanResult;

  const filterTabs: { key: SeverityFilter; label: string; count: number; color: string }[] = [
    { key: "all", label: "All", count: summary.total, color: "text-white" },
    { key: "critical", label: "Critical", count: summary.critical, color: "text-red-400" },
    { key: "high", label: "High", count: summary.high, color: "text-orange-400" },
    { key: "medium", label: "Medium", count: summary.medium, color: "text-yellow-400" },
    { key: "low", label: "Low", count: summary.low, color: "text-blue-400" },
    { key: "info", label: "Info", count: summary.info, color: "text-gray-400" },
  ];

  return (
    <div className="min-h-screen cyber-grid py-10">
      <div className="max-w-7xl mx-auto px-4">
        {/* Top navigation */}
        <div className="flex items-center justify-between mb-8">
          <Link
            href="/scanner"
            className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors text-sm"
          >
            <ChevronLeft className="w-4 h-4" />
            Back to Scanner
          </Link>
          <div className="flex items-center gap-3">
            <button
              onClick={handleDownloadReport}
              disabled={isDownloading}
              className="flex items-center gap-2 px-4 py-2 rounded-lg border border-gray-700 hover:border-gray-600 text-gray-300 hover:text-white text-sm transition-all"
            >
              {isDownloading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
              Download Report
            </button>
            <button
              onClick={handleGenerateAllPatches}
              className="flex items-center gap-2 px-5 py-2 bg-gradient-to-r from-cyan-500 to-emerald-500 text-gray-950 font-bold rounded-lg text-sm hover:opacity-90 glow-cyan transition-all"
            >
              <Sparkles className="w-4 h-4" />
              Generate All Patches
            </button>
          </div>
        </div>

        {/* Scan Header */}
        <div className="p-6 rounded-2xl bg-gray-900 border border-gray-800 mb-8">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
            <div>
              <span className="font-mono text-xs text-cyan-400">Scan ID: {scanResult.scan_id}</span>
              <h1 className="text-2xl font-bold text-white mt-1">Vulnerability Findings</h1>
              <p className="text-gray-400 text-sm mt-0.5">
                Target: <span className="text-cyan-400 font-mono">{scanResult.filename}</span> · Language: {scanResult.language}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-500 font-mono">
                {new Date(scanResult.scanned_at).toLocaleString()}
              </span>
            </div>
          </div>

          {/* Severity Counters */}
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
            {filterTabs.map((tab) => (
              <button
                key={tab.key}
                onClick={() => setFilter(tab.key)}
                className={`p-3 rounded-xl border text-left transition-all ${
                  filter === tab.key
                    ? "bg-gray-800 border-cyan-500/50"
                    : "bg-gray-950/50 border-gray-800 hover:border-gray-700"
                }`}
              >
                <span className="text-xs text-gray-400 block mb-1">{tab.label}</span>
                <span className={`text-2xl font-bold font-mono ${tab.color}`}>{tab.count}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Vulnerability List */}
        {filtered.length === 0 ? (
          <div className="p-12 text-center rounded-2xl bg-gray-900 border border-gray-800">
            <CheckCircle className="w-12 h-12 text-emerald-400 mx-auto mb-3" />
            <h3 className="text-lg font-semibold text-white">No vulnerabilities in this filter</h3>
            <p className="text-gray-400 text-sm mt-1">Select &quot;All&quot; to see all findings.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {filtered.map((vuln) => (
              <VulnerabilityCard key={vuln.id} vuln={vuln} scanId={scanResult.scan_id} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
