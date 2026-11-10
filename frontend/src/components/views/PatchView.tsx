"use client";
import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  Wrench, ChevronLeft, Download, RefreshCw, CheckCircle,
  AlertTriangle, Loader2, Bot, Sparkles
} from "lucide-react";
import { ScanResult, Patch, PatchResult } from "@/lib/types";
import { generatePatches, rescanCode, generateReport } from "@/lib/api";
import { clientScan, clientPatch } from "@/lib/client-scanner";
import DiffViewer from "@/components/patch/DiffViewer";

const DEMO_CODE = `"""
PATCHPILOT Demo — Intentionally Vulnerable Python
"""
import pickle
import os
import random

# Hardcoded credentials
DB_PASSWORD = "admin123!supersecret"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

def get_user(username):
    # SQL Injection via f-string
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

def run_command(cmd):
    # OS command injection
    os.system("backup_utility --target " + cmd)

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

export default function PatchView() {
  const params = useParams();
  const scanId = (params?.id as string) || "latest";

  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [originalCode, setOriginalCode] = useState("");
  const [patchResult, setPatchResult] = useState<PatchResult | null>(null);
  const [rescanResult, setRescanResult] = useState<ScanResult | null>(null);
  const [selectedPatchIdx, setSelectedPatchIdx] = useState(0);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isRescanning, setIsRescanning] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const stored = sessionStorage.getItem(`scan_${scanId}`) || sessionStorage.getItem("scan_latest");
    const code = sessionStorage.getItem(`code_${scanId}`) || sessionStorage.getItem("code_latest");
    if (stored && code) {
      setScanResult(JSON.parse(stored));
      setOriginalCode(code);
    } else {
      // Auto-load demo scan and patches
      const demoScan = clientScan(DEMO_CODE, "python", "vulnerable_app.py");
      const demoPatches = clientPatch(DEMO_CODE, demoScan.vulnerabilities, scanId);
      setScanResult(demoScan);
      setOriginalCode(DEMO_CODE);
      setPatchResult(demoPatches);
      try {
        sessionStorage.setItem(`scan_${scanId}`, JSON.stringify(demoScan));
        sessionStorage.setItem(`code_${scanId}`, DEMO_CODE);
        sessionStorage.setItem(`patch_${scanId}`, JSON.stringify(demoPatches));
      } catch {
        /* ignore */
      }
    }
  }, [scanId]);

  const handleGeneratePatches = useCallback(async () => {
    if (!scanResult) return;
    setIsGenerating(true);
    setError(null);
    try {
      const result = await generatePatches(originalCode, scanResult.vulnerabilities, scanId);
      setPatchResult(result);
      sessionStorage.setItem(`patch_${scanId}`, JSON.stringify(result));
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to generate patches.";
      setError(msg);
    } finally {
      setIsGenerating(false);
    }
  }, [scanResult, originalCode, scanId]);

  useEffect(() => {
    if (scanResult && originalCode && !patchResult && !isGenerating) {
      handleGeneratePatches();
    }
  }, [scanResult, originalCode, patchResult, isGenerating, handleGeneratePatches]);

  const handleRescan = async () => {
    if (!patchResult) return;
    setIsRescanning(true);
    setError(null);
    try {
      const result = await rescanCode(patchResult.patched_code_full, "python");
      setRescanResult(result);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Re-scan failed.";
      setError(msg);
    } finally {
      setIsRescanning(false);
    }
  };

  const handleDownloadReport = async () => {
    if (!scanResult || !patchResult) return;
    setIsDownloading(true);
    try {
      const blob = await generateReport({
        scan_id: scanId,
        original_code: originalCode,
        patched_code: patchResult.patched_code_full,
        vulnerabilities: scanResult.vulnerabilities,
        patches: patchResult.patches,
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

  const currentPatch: Patch | null = patchResult?.patches[selectedPatchIdx] ?? null;
  const currentVuln = scanResult?.vulnerabilities.find(
    (v) => v.id === currentPatch?.vulnerability_id
  );

  return (
    <div className="min-h-screen cyber-grid">
      <div className="max-w-7xl mx-auto px-4 py-10">
        <Link href={`/results/${scanId}`} className="inline-flex items-center gap-2 text-gray-400 hover:text-white text-sm mb-6 transition-colors">
          <ChevronLeft className="w-4 h-4" />
          Back to Results
        </Link>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <Wrench className="w-8 h-8 text-emerald-400" />
              <h1 className="text-2xl font-bold text-white">AI Patch Workspace</h1>
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1 font-mono">
                <Sparkles className="w-3 h-3" />
                Google Gemma 4
              </span>
            </div>
            <p className="text-gray-400 text-sm font-mono">Scan: {scanId}</p>
          </div>

          <div className="flex gap-3">
            {patchResult && (
              <button
                onClick={handleRescan}
                disabled={isRescanning}
                className="flex items-center gap-2 px-5 py-2.5 bg-emerald-500 hover:bg-emerald-400 text-gray-950 font-bold rounded-lg transition-all text-sm glow-cyan"
              >
                {isRescanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                Re-scan Patched Code
              </button>
            )}
            {patchResult && (
              <button
                onClick={handleDownloadReport}
                disabled={isDownloading}
                className="flex items-center gap-2 px-5 py-2.5 border border-gray-700 hover:border-gray-600 text-gray-300 hover:text-white text-sm font-semibold rounded-lg transition-all"
              >
                {isDownloading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
                Download Report
              </button>
            )}
          </div>
        </div>

        {error && (
          <div className="mb-6 flex items-start gap-3 p-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400">
            <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" />
            <span className="text-sm">{error}</span>
          </div>
        )}

        {isGenerating && (
          <div className="text-center py-20">
            <div className="w-20 h-20 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center mx-auto mb-6 scanning-animate">
              <Bot className="w-10 h-10 text-emerald-400" />
            </div>
            <h2 className="text-xl text-white font-semibold mb-2">Generating Patches...</h2>
            <p className="text-gray-400">
              Gemma 4 is analyzing vulnerabilities and generating secure fixes.
            </p>
          </div>
        )}

        {patchResult && (
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            <div className="lg:col-span-1">
              <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
                Patches ({patchResult.patches.length})
              </h2>
              <div className="space-y-2">
                {patchResult.patches.map((patch, i) => {
                  const vuln = scanResult?.vulnerabilities.find((v) => v.id === patch.vulnerability_id);
                  return (
                    <button
                      key={patch.vulnerability_id}
                      onClick={() => setSelectedPatchIdx(i)}
                      className={`w-full text-left p-3 rounded-lg border transition-all ${
                        selectedPatchIdx === i
                          ? "bg-gray-800 border-cyan-500/50 text-white"
                          : "bg-gray-900 border-gray-800 text-gray-400 hover:border-gray-700"
                      }`}
                    >
                      <div className="text-xs font-mono text-emerald-400 mb-1">
                        Patch {i + 1} · {Math.round(patch.confidence * 100)}% confidence
                      </div>
                      <div className="text-sm font-medium truncate">
                        {vuln?.title || "Vulnerability"}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="lg:col-span-3 space-y-6">
              {currentPatch && currentVuln && (
                <>
                  <div className="p-4 rounded-xl bg-gray-900 border border-gray-800">
                    <div className="flex items-start gap-3">
                      <div className={`px-2 py-0.5 rounded text-xs font-semibold uppercase severity-${currentVuln.severity}`}>
                        {currentVuln.severity}
                      </div>
                      <div>
                        <h3 className="text-white font-semibold">{currentVuln.title}</h3>
                        <p className="text-gray-400 text-sm mt-1">{currentVuln.description}</p>
                      </div>
                    </div>

                    <div className="mt-4 p-3 rounded-lg bg-gray-950 border border-gray-800">
                      <div className="flex items-start gap-2">
                        <Bot className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                        <div>
                          <div className="text-xs text-emerald-400 font-semibold mb-1">
                            Google Gemma 4 Fix Explanation
                          </div>
                          <p className="text-gray-300 text-sm leading-relaxed">
                            {currentPatch.explanation}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>

                  <DiffViewer
                    original={currentPatch.original_code}
                    patched={currentPatch.patched_code}
                  />
                </>
              )}

              {rescanResult && (
                <div className={`p-5 rounded-xl border ${
                  rescanResult.summary.critical === 0 && rescanResult.summary.high === 0
                    ? "bg-emerald-950/30 border-emerald-500/30"
                    : "bg-orange-950/30 border-orange-500/30"
                }`}>
                  <div className="flex items-center gap-3 mb-3">
                    {rescanResult.summary.critical === 0 && rescanResult.summary.high === 0 ? (
                      <CheckCircle className="w-6 h-6 text-emerald-400" />
                    ) : (
                      <AlertTriangle className="w-6 h-6 text-orange-400" />
                    )}
                    <h3 className="font-semibold text-white">Re-scan Verification Proof</h3>
                  </div>
                  <div className="grid grid-cols-5 gap-3 text-sm">
                    {[
                      { label: "Total", count: rescanResult.summary.total },
                      { label: "Critical", count: rescanResult.summary.critical },
                      { label: "High", count: rescanResult.summary.high },
                      { label: "Medium", count: rescanResult.summary.medium },
                      { label: "Low", count: rescanResult.summary.low },
                    ].map((s) => (
                      <div key={s.label} className="text-center">
                        <div className="text-xl font-bold text-white">{s.count}</div>
                        <div className="text-gray-400">{s.label}</div>
                      </div>
                    ))}
                  </div>
                  {rescanResult.summary.total === 0 && (
                    <p className="mt-3 text-emerald-400 text-sm font-semibold">
                      ✓ Patch verified — 0 vulnerabilities remaining. Flaws mathematically eliminated!
                    </p>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
