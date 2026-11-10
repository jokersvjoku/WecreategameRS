"use client";
import React, { useState, useCallback, Suspense, useEffect } from "react";
import { useSearchParams } from "next/navigation";
import dynamic from "next/dynamic";
import {
  Shield, Play, Code2, AlertCircle, Loader2, Sparkles,
  CheckCircle2, RefreshCw, Download, AlertTriangle,
} from "lucide-react";
import { scanCode, generatePatches, rescanCode, generateReport } from "@/lib/api";
import { ScanResult, PatchResult } from "@/lib/types";
import FileUpload from "@/components/scanner/FileUpload";
import DiffViewer from "@/components/patch/DiffViewer";
import SeverityBadge from "@/components/results/SeverityBadge";
import type { Metadata } from "next";

const CodeEditor = dynamic(() => import("@/components/scanner/CodeEditor"), {
  ssr: false,
  loading: () => (
    <div className="h-96 bg-gray-900 border border-gray-800 rounded-lg flex items-center justify-center">
      <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
    </div>
  ),
});

const PRESETS = {
  full: `"""
PATCHPILOT Demo — Intentionally Vulnerable Python Suite
Find the flaw. Fix the code. Prove the patch.
"""
import os
import pickle
import random

# CWE-798: Hardcoded Credentials
DB_PASSWORD = "admin123!supersecret"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

def get_user_records(username: str):
    # CWE-89: SQL Injection via f-string formatting
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

def execute_user_utility(user_command: str):
    # CWE-78: OS Command Injection
    os.system("backup_utility --target " + user_command)

def calculate_formula(expression: str):
    # CWE-95: Dangerous Code Injection via eval()
    return eval(expression)

def restore_session_payload(data: bytes):
    # CWE-502: Insecure Deserialization via pickle
    return pickle.loads(data)

from flask import Flask
app = Flask(__name__)
# CWE-94: Security Misconfiguration — debug exposes interactive debugger in prod
app.run(debug=True, host="0.0.0.0")
`,
  sqli: `"""
SQL Injection Vulnerability Example (CWE-89)
"""
import sqlite3

def find_account(account_id: str):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # Vulnerable: unsanitized string concatenation into SQL
    query = "SELECT balance, ssn FROM accounts WHERE id = '" + account_id + "'"
    cursor.execute(query)
    return cursor.fetchone()
`,
  creds: `"""
Hardcoded Secrets & API Keys Example (CWE-798)
"""
DATABASE_PASSWORD = "prod_db_master_password_99#"
API_SECRET_TOKEN = "sec_demo_credential_token_value_99999"
AUTH_ACCESS_TOKEN = "token_example_mock_9999999999999999"

def connect_db():
    print("Connecting with secret credentials...")
`,
  eval: `"""
Arbitrary Code & Command Injection Example (CWE-95 / CWE-78)
"""
import os

def run_math_engine(user_input: str):
    # Dangerous eval of untrusted client input
    result = eval(user_input)
    return result

def ping_server(target_ip: str):
    # Command injection via shell command string
    os.system("ping -c 1 " + target_ip)
`,
};

function saveSessionStats(vulnCount: number, patchCount: number, scanId: string) {
  try {
    const raw = sessionStorage.getItem("pp_stats");
    const prev = raw ? JSON.parse(raw) : { totalScans: 0, totalVulns: 0, patchesApplied: 0, lastScanId: null };
    sessionStorage.setItem("pp_stats", JSON.stringify({
      totalScans: prev.totalScans + 1,
      totalVulns: prev.totalVulns + vulnCount,
      patchesApplied: prev.patchesApplied + patchCount,
      lastScanId: scanId,
    }));
  } catch {
    /* ignore quota */
  }
}

export default function ScannerPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen flex items-center justify-center">
          <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
        </div>
      }
    >
      <ScannerWorkspace />
    </Suspense>
  );
}

function ScannerWorkspace() {
  const searchParams = useSearchParams();
  const isDemo = searchParams.get("demo") === "true";

  const [code, setCode] = useState(PRESETS.full);
  const [filename, setFilename] = useState("vulnerable_app.py");
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Patching & Verification state
  const [isPatching, setIsPatching] = useState(false);
  const [patchResult, setPatchResult] = useState<PatchResult | null>(null);
  const [isRescanning, setIsRescanning] = useState(false);
  const [rescanResult, setRescanResult] = useState<ScanResult | null>(null);
  const [activeSeverity, setActiveSeverity] = useState<string>("all");
  const [isDownloading, setIsDownloading] = useState(false);

  const showSuccess = (msg: string) => {
    setSuccessMsg(msg);
    setTimeout(() => setSuccessMsg(null), 4000);
  };

  const handleScan = useCallback(async (codeToScan?: string, fileToScan?: string) => {
    const targetCode = codeToScan ?? code;
    const targetFile = fileToScan ?? filename;

    if (!targetCode.trim()) {
      setError("Please paste or upload Python code to scan.");
      return;
    }

    setError(null);
    setSuccessMsg(null);
    setIsScanning(true);
    setPatchResult(null);
    setRescanResult(null);
    setScanResult(null);

    try {
      const result: ScanResult = await scanCode(targetCode, "python", targetFile);
      setScanResult(result);
      showSuccess(
        result.summary.total === 0
          ? "✓ Scan complete — no vulnerabilities found."
          : `✓ Scan complete — found ${result.summary.total} vulnerabilities.`
      );

      try {
        sessionStorage.setItem("scan_latest", JSON.stringify(result));
        sessionStorage.setItem(`scan_${result.scan_id}`, JSON.stringify(result));
        sessionStorage.setItem("code_latest", targetCode);
        sessionStorage.setItem(`code_${result.scan_id}`, targetCode);
        saveSessionStats(result.summary.total, 0, result.scan_id);
      } catch {
        /* ignore storage quota */
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Scanning failed. Please try again.";
      setError(msg);
    } finally {
      setIsScanning(false);
    }
  }, [code, filename]);

  useEffect(() => {
    if (isDemo && !scanResult) {
      handleScan(PRESETS.full, "demo_suite.py");
    }
  }, [isDemo, scanResult, handleScan]);

  const handleLoadPreset = (key: keyof typeof PRESETS, label: string) => {
    setCode(PRESETS[key]);
    setFilename(label);
    setError(null);
    setSuccessMsg(null);
    setScanResult(null);
    setPatchResult(null);
    setRescanResult(null);
  };

  const handleGeneratePatches = async () => {
    if (!scanResult) return;
    setIsPatching(true);
    setError(null);

    try {
      const patches = await generatePatches(code, scanResult.vulnerabilities, scanResult.scan_id);
      setPatchResult(patches);
      showSuccess(`✓ ${patches.patches.length} patches generated. Review the diff below.`);

      try {
        sessionStorage.setItem("patch_latest", JSON.stringify(patches));
        sessionStorage.setItem(`patch_${scanResult.scan_id}`, JSON.stringify(patches));
        // Update stats for patches
        const raw = sessionStorage.getItem("pp_stats");
        if (raw) {
          const prev = JSON.parse(raw);
          sessionStorage.setItem("pp_stats", JSON.stringify({ ...prev, patchesApplied: prev.patchesApplied + patches.patches.length }));
        }
      } catch {
        /* ignore */
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Patch generation failed. Please try again.";
      setError(msg);
    } finally {
      setIsPatching(false);
    }
  };

  const handleRescanPatched = async () => {
    if (!patchResult) return;
    setIsRescanning(true);
    setError(null);
    try {
      const result = await rescanCode(patchResult.patched_code_full, "python");
      setRescanResult(result);
      showSuccess(
        result.summary.total === 0
          ? "✓ Re-scan verified — all vulnerabilities eliminated by patches."
          : `Re-scan found ${result.summary.total} remaining advisories.`
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Re-scan failed. Please try again.";
      setError(msg);
    } finally {
      setIsRescanning(false);
    }
  };

  const handleDownloadReport = async () => {
    if (!scanResult) return;
    setIsDownloading(true);
    try {
      const blob = await generateReport({
        scan_id: scanResult.scan_id,
        original_code: code,
        patched_code: patchResult?.patched_code_full,
        vulnerabilities: scanResult.vulnerabilities,
        patches: patchResult?.patches,
      });

      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `patchpilot-report-${scanResult.scan_id.slice(0, 8)}.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showSuccess("✓ Security audit report downloaded.");
    } catch {
      setError("Failed to generate the security audit report. Please try again.");
    } finally {
      setIsDownloading(false);
    }
  };

  const filteredVulns = scanResult
    ? activeSeverity === "all"
      ? scanResult.vulnerabilities
      : scanResult.vulnerabilities.filter((v) => v.severity === activeSeverity)
    : [];

  return (
    <div className="min-h-screen cyber-grid py-6 px-4 overflow-x-hidden">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Page Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-gray-800 pb-5">
          <div className="flex items-center gap-3 min-w-0">
            <div className="shrink-0 w-10 h-10 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center">
              <Shield className="w-5 h-5 text-cyan-400" />
            </div>
            <div className="min-w-0">
              <h1 className="text-xl md:text-2xl font-bold text-white tracking-tight truncate">
                Security Scanning & Patch Studio
              </h1>
              <p className="text-xs text-gray-500 hidden sm:block">
                AST Static Analysis · Google Gemma 4 Remediation · Proof-of-fix Verification
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Engine Online
            </span>
          </div>
        </div>

        {/* Notifications */}
        {successMsg && (
          <div className="p-3 rounded-xl bg-emerald-950/40 border border-emerald-500/30 text-emerald-400 text-sm flex items-center gap-3 animate-in fade-in-50 duration-200">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}
        {error && (
          <div className="p-3 rounded-xl bg-red-950/40 border border-red-500/30 text-red-400 text-sm flex items-center gap-3">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span className="flex-1">{error}</span>
            <button onClick={() => setError(null)} className="shrink-0 text-red-400/60 hover:text-red-300 text-xs font-mono" aria-label="Dismiss error">✕</button>
          </div>
        )}

        {/* Preset & Upload Toolbar */}
        <div className="p-3 bg-gray-900/60 rounded-xl border border-gray-800">
          <div className="flex flex-wrap items-start gap-3">
            <div className="flex flex-wrap items-center gap-2 flex-1 min-w-0">
              <span className="text-gray-500 text-xs font-semibold uppercase tracking-wider shrink-0">Presets:</span>
              {[
                { key: "full" as const, label: "vulnerable_suite.py", name: "Full Suite" },
                { key: "sqli" as const, label: "sqli_vuln.py", name: "SQL Injection" },
                { key: "creds" as const, label: "secrets_leak.py", name: "Credentials" },
                { key: "eval" as const, label: "code_exec.py", name: "Eval / OS Cmd" },
              ].map(({ key, label, name }) => (
                <button
                  key={key}
                  onClick={() => handleLoadPreset(key, label)}
                  className="px-2.5 py-1 rounded-lg bg-gray-800 hover:bg-gray-700 hover:text-white text-gray-300 font-mono text-xs transition-all border border-transparent hover:border-gray-600 whitespace-nowrap"
                >
                  {name}
                </button>
              ))}
            </div>
            <FileUpload
              onFileUpload={(content, name) => {
                setCode(content);
                setFilename(name);
                setError(null);
                setScanResult(null);
                setSuccessMsg(null);
              }}
            />
          </div>
        </div>

        {/* Editor Section */}
        <div className="space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-xs font-mono text-gray-400 min-w-0">
              <Code2 className="w-4 h-4 text-cyan-400 shrink-0" />
              <span className="truncate">
                <span className="text-gray-500">Target: </span>
                <strong className="text-white">{filename}</strong>
              </span>
              <span className="text-gray-700 hidden sm:inline">·</span>
              <span className="hidden sm:inline">{code.split("\n").length} lines</span>
            </div>

            <button
              onClick={() => handleScan()}
              disabled={isScanning}
              className="flex items-center gap-2 px-5 py-2 bg-cyan-500 hover:bg-cyan-400 active:bg-cyan-600 disabled:bg-cyan-900 disabled:cursor-not-allowed text-gray-950 font-bold rounded-lg transition-all glow-cyan text-sm shrink-0 focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:ring-offset-2 focus:ring-offset-gray-950"
              aria-label={isScanning ? "Scanning code..." : "Scan code for vulnerabilities"}
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Analyzing AST…</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  <span>Scan Code</span>
                </>
              )}
            </button>
          </div>

          <CodeEditor value={code} onChange={(val) => setCode(val || "")} />
        </div>

        {/* Scan Results */}
        {scanResult && (
          <div className="space-y-5 pt-4 border-t border-gray-800">
            {/* Results Summary */}
            <div className="p-5 bg-gray-900 rounded-2xl border border-gray-800 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
                <div className="min-w-0">
                  <p className="text-xs font-mono text-cyan-400 mb-1 truncate">
                    Scan ID: {scanResult.scan_id}
                  </p>
                  <h2 className="text-xl md:text-2xl font-bold text-white">
                    {scanResult.summary.total === 0
                      ? "No vulnerabilities detected"
                      : `Found ${scanResult.summary.total} vulnerabilit${scanResult.summary.total === 1 ? "y" : "ies"}`}
                  </h2>
                  <p className="text-xs text-gray-500 mt-1">
                    {scanResult.filename} · {new Date(scanResult.scanned_at).toLocaleTimeString()}
                  </p>
                </div>

                <div className="flex flex-wrap gap-2 shrink-0">
                  <button
                    onClick={handleGeneratePatches}
                    disabled={isPatching || scanResult.vulnerabilities.length === 0}
                    className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-500 to-emerald-500 hover:opacity-90 active:opacity-80 disabled:opacity-40 disabled:cursor-not-allowed text-gray-950 font-bold rounded-xl transition-all text-sm whitespace-nowrap focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:ring-offset-2 focus:ring-offset-gray-900"
                    title={scanResult.vulnerabilities.length === 0 ? "No vulnerabilities to patch" : "Generate AI patches"}
                  >
                    {isPatching ? (
                      <><Loader2 className="w-4 h-4 animate-spin" /><span>Generating…</span></>
                    ) : (
                      <><Sparkles className="w-4 h-4" /><span>Fix with Gemma 4</span></>
                    )}
                  </button>

                  <button
                    onClick={handleDownloadReport}
                    disabled={isDownloading}
                    className="flex items-center gap-2 px-4 py-2 rounded-xl border border-gray-700 hover:border-gray-500 text-gray-300 hover:text-white text-sm font-semibold transition-all disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
                  >
                    {isDownloading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
                    <span>Report</span>
                  </button>
                </div>
              </div>

              {/* Severity filter tabs */}
              <div className="grid grid-cols-3 sm:grid-cols-6 gap-2 pt-1">
                {[
                  { key: "all", label: "ALL", count: scanResult.summary.total, active: "border-cyan-400 bg-gray-800", base: "text-white" },
                  { key: "critical", label: "CRIT", count: scanResult.summary.critical, active: "border-red-500 bg-red-950/40", base: "text-red-400" },
                  { key: "high", label: "HIGH", count: scanResult.summary.high, active: "border-orange-500 bg-orange-950/40", base: "text-orange-400" },
                  { key: "medium", label: "MED", count: scanResult.summary.medium, active: "border-yellow-500 bg-yellow-950/40", base: "text-yellow-400" },
                  { key: "low", label: "LOW", count: scanResult.summary.low, active: "border-blue-500 bg-blue-950/40", base: "text-blue-400" },
                  { key: "info", label: "INFO", count: scanResult.summary.info, active: "border-gray-500 bg-gray-800", base: "text-gray-400" },
                ].map(({ key, label, count, active, base }) => (
                  <button
                    key={key}
                    onClick={() => setActiveSeverity(key)}
                    className={`p-2.5 rounded-xl border cursor-pointer transition-all text-left focus:outline-none focus:ring-2 focus:ring-cyan-500/50 ${activeSeverity === key ? active : "bg-gray-900/50 border-gray-800 hover:border-gray-700"}`}
                    aria-pressed={activeSeverity === key}
                    aria-label={`Filter by ${label}: ${count} findings`}
                  >
                    <div className={`text-[10px] font-mono ${activeSeverity === key ? base : "text-gray-500"}`}>{label}</div>
                    <div className={`text-xl font-bold font-mono ${activeSeverity === key ? base : "text-gray-300"}`}>{count}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Vulnerability list */}
            {filteredVulns.length > 0 ? (
              <div className="space-y-3">
                <h3 className="text-base font-semibold text-white flex items-center gap-2">
                  Vulnerabilities
                  <span className="text-xs font-mono text-gray-500 bg-gray-800 px-2 py-0.5 rounded-full">
                    {filteredVulns.length}
                  </span>
                </h3>

                {filteredVulns.map((vuln) => (
                  <div
                    key={vuln.id}
                    className="p-4 rounded-xl bg-gray-900/90 border border-gray-800 hover:border-gray-700 space-y-3 transition-all"
                  >
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div className="flex items-center gap-2 flex-wrap min-w-0">
                        <SeverityBadge severity={vuln.severity} />
                        <span className="font-semibold text-white text-sm">{vuln.title}</span>
                      </div>
                      <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono text-gray-500 shrink-0">
                        {vuln.cwe_id && (
                          <a
                            href={`https://cwe.mitre.org/data/definitions/${vuln.cwe_id.replace("CWE-", "")}.html`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="bg-gray-800 px-2 py-0.5 rounded text-cyan-400 hover:text-cyan-300 transition-colors"
                            title={`View ${vuln.cwe_id} on MITRE CWE`}
                          >
                            {vuln.cwe_id}
                          </a>
                        )}
                        <span className="bg-gray-800 px-2 py-0.5 rounded">{vuln.rule_id}</span>
                        <span className="text-gray-600">L{vuln.line_start}</span>
                      </div>
                    </div>

                    <p className="text-sm text-gray-400 leading-relaxed">{vuln.description}</p>

                    {vuln.code_snippet && (
                      <div className="rounded-lg bg-gray-950 border border-red-500/20 overflow-hidden">
                        <div className="px-3 py-1.5 bg-red-500/5 border-b border-red-500/10 text-[10px] font-mono text-gray-500 uppercase tracking-wider">
                          Vulnerable snippet — Line {vuln.line_start}
                        </div>
                        <pre className="p-3 text-xs text-red-300 font-mono overflow-x-auto whitespace-pre-wrap break-words">
                          {vuln.code_snippet}
                        </pre>
                      </div>
                    )}

                    <div className="text-xs text-emerald-400/90 bg-emerald-950/20 border border-emerald-500/20 p-3 rounded-lg flex items-start gap-2">
                      <Sparkles className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" aria-hidden="true" />
                      <div>
                        <strong className="text-emerald-300">Remediation: </strong>
                        <span>{vuln.recommendation}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              scanResult.summary.total > 0 && (
                <div className="p-6 text-center rounded-xl bg-gray-900 border border-gray-800 text-gray-400 text-sm">
                  No vulnerabilities match the selected severity filter.
                </div>
              )
            )}

            {/* Patches & Diff Section */}
            {patchResult && (
              <div className="pt-4 border-t border-gray-800 space-y-5">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div>
                    <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-mono mb-2">
                      <Sparkles className="w-3 h-3" />
                      {patchResult.patches.length} patches synthesized by Google Gemma 4
                    </div>
                    <h2 className="text-xl font-bold text-white">Patched Code — Side-by-Side Diff</h2>
                    <p className="text-sm text-gray-400 mt-0.5">
                      Applied {patchResult.patches.length} security patch{patchResult.patches.length !== 1 ? "es" : ""} to source code.
                    </p>
                  </div>

                  <button
                    onClick={handleRescanPatched}
                    disabled={isRescanning}
                    className="flex items-center gap-2 px-5 py-2.5 bg-emerald-500 hover:bg-emerald-400 active:bg-emerald-600 disabled:bg-emerald-900 disabled:cursor-not-allowed text-gray-950 font-bold rounded-xl transition-all text-sm shrink-0 whitespace-nowrap focus:outline-none focus:ring-2 focus:ring-emerald-400 focus:ring-offset-2 focus:ring-offset-gray-950"
                  >
                    {isRescanning ? (
                      <><Loader2 className="w-4 h-4 animate-spin" /><span>Re-scanning…</span></>
                    ) : (
                      <><RefreshCw className="w-4 h-4" /><span>Re-scan & Prove</span></>
                    )}
                  </button>
                </div>

                <DiffViewer original={code} patched={patchResult.patched_code_full} />

                {/* Verification Result */}
                {rescanResult && (
                  <div
                    className={`p-5 rounded-2xl border-2 space-y-3 ${
                      rescanResult.summary.total === 0
                        ? "bg-emerald-950/30 border-emerald-500/50"
                        : "bg-orange-950/20 border-orange-500/40"
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <div className={`w-10 h-10 rounded-full flex items-center justify-center border shrink-0 ${
                        rescanResult.summary.total === 0
                          ? "bg-emerald-500/20 border-emerald-500/40"
                          : "bg-orange-500/20 border-orange-500/40"
                      }`}>
                        {rescanResult.summary.total === 0
                          ? <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                          : <AlertTriangle className="w-5 h-5 text-orange-400" />
                        }
                      </div>
                      <div>
                        <h3 className="text-lg font-bold text-white">
                          {rescanResult.summary.total === 0
                            ? "Patch Verified — All Vulnerabilities Eliminated"
                            : `${rescanResult.summary.total} Remaining Advisories`}
                        </h3>
                        <p className={`text-sm ${rescanResult.summary.total === 0 ? "text-emerald-300" : "text-orange-300"}`}>
                          {rescanResult.summary.total === 0
                            ? "100% of detected CWEs neutralised. Code is production-safe."
                            : "Review remaining findings and re-apply patches as needed."}
                        </p>
                      </div>
                    </div>

                    <button
                      onClick={handleDownloadReport}
                      disabled={isDownloading}
                      className="inline-flex items-center gap-2 px-5 py-2.5 bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-gray-950 font-bold rounded-xl transition-all text-sm"
                    >
                      {isDownloading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
                      Download Verified Audit Report
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
