"use client";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { FileText, ChevronLeft, Download, Loader2, XCircle, CheckCircle, AlertTriangle } from "lucide-react";
import { ScanResult, PatchResult } from "@/lib/types";
import { generateReport } from "@/lib/api";
import { clientScan, clientPatch } from "@/lib/client-scanner";
import SeverityBadge from "@/components/results/SeverityBadge";

const DEMO_CODE = `import os\nimport pickle\n\nDB_PASSWORD = "admin123!supersecret"\n\ndef get_user(u):\n    return cursor.execute(f"SELECT * FROM users WHERE name = '{u}'")\n`;

export default function ReportView() {
  const params = useParams();
  const scanId = (params?.id as string) || "latest";

  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [patchResult, setPatchResult] = useState<PatchResult | null>(null);
  const [originalCode, setOriginalCode] = useState("");
  const [isDownloading, setIsDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const stored = sessionStorage.getItem(`scan_${scanId}`) || sessionStorage.getItem("scan_latest");
    const code = sessionStorage.getItem(`code_${scanId}`) || sessionStorage.getItem("code_latest");
    const patch = sessionStorage.getItem(`patch_${scanId}`) || sessionStorage.getItem("patch_latest");
    if (stored) setScanResult(JSON.parse(stored));
    if (code) setOriginalCode(code);
    if (patch) setPatchResult(JSON.parse(patch));
    if (!stored) {
      const demoScan = clientScan(DEMO_CODE, "python", "vulnerable_app.py");
      const demoPatch = clientPatch(DEMO_CODE, demoScan.vulnerabilities, scanId);
      setScanResult(demoScan);
      setOriginalCode(DEMO_CODE);
      setPatchResult(demoPatch);
    }
  }, [scanId]);

  const handleDownload = async () => {
    if (!scanResult) return;
    setIsDownloading(true);
    try {
      const blob = await generateReport({
        scan_id: scanId,
        original_code: originalCode,
        patched_code: patchResult?.patched_code_full,
        vulnerabilities: scanResult.vulnerabilities,
        patches: patchResult?.patches,
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

  if (error && !scanResult) {
    return (
      <div className="min-h-screen flex items-center justify-center cyber-grid">
        <div className="text-center">
          <XCircle className="w-16 h-16 text-red-400 mx-auto mb-4" />
          <h2 className="text-xl text-white font-semibold mb-2">Report Not Found</h2>
          <p className="text-gray-400 mb-6">{error}</p>
          <Link href="/scanner" className="px-6 py-3 bg-cyan-500 text-gray-950 font-bold rounded-lg">
            Start New Scan
          </Link>
        </div>
      </div>
    );
  }

  if (!scanResult) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  const { summary } = scanResult;

  return (
    <div className="min-h-screen cyber-grid">
      <div className="max-w-5xl mx-auto px-4 py-10">
        <Link href={`/results/${scanId}`} className="inline-flex items-center gap-2 text-gray-400 hover:text-white text-sm mb-6 transition-colors">
          <ChevronLeft className="w-4 h-4" />
          Back to Results
        </Link>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
          <div className="flex items-center gap-3">
            <FileText className="w-8 h-8 text-cyan-400" />
            <div>
              <h1 className="text-2xl font-bold text-white">Security Report</h1>
              <p className="text-gray-400 text-sm font-mono">Scan: {scanId}</p>
            </div>
          </div>
          <button
            onClick={handleDownload}
            disabled={isDownloading}
            className="flex items-center gap-2 px-6 py-3 bg-cyan-500 hover:bg-cyan-400 text-gray-950 font-bold rounded-lg transition-all glow-cyan"
          >
            {isDownloading ? (
              <><Loader2 className="w-5 h-5 animate-spin" /> Preparing Report...</>
            ) : (
              <><Download className="w-5 h-5" /> Download Report</>
            )}
          </button>
        </div>

        <div className="space-y-6">
          <div className="p-6 rounded-xl bg-gray-900 border border-gray-800">
            <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              Executive Summary
            </h2>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              {[
                { label: "Total Issues", value: summary.total, color: "text-white" },
                { label: "Critical", value: summary.critical, color: "text-red-400" },
                { label: "High", value: summary.high, color: "text-orange-400" },
                { label: "Patches", value: patchResult?.patches.length ?? 0, color: "text-emerald-400" },
              ].map((s) => (
                <div key={s.label} className="text-center p-4 rounded-lg bg-gray-950">
                  <div className={`text-3xl font-bold mb-1 ${s.color}`}>{s.value}</div>
                  <div className="text-gray-400 text-sm">{s.label}</div>
                </div>
              ))}
            </div>

            <div className="mt-4 flex items-center gap-2">
              {summary.critical === 0 && summary.high === 0 ? (
                <><CheckCircle className="w-5 h-5 text-emerald-400" /><span className="text-emerald-400 text-sm">No critical or high severity vulnerabilities found.</span></>
              ) : (
                <><AlertTriangle className="w-5 h-5 text-orange-400" /><span className="text-orange-400 text-sm">Action required: {summary.critical} critical, {summary.high} high severity issues detected.</span></>
              )}
            </div>
          </div>

          <div className="p-6 rounded-xl bg-gray-900 border border-gray-800">
            <h2 className="text-lg font-semibold text-white mb-4">Scan Details</h2>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div><span className="text-gray-400">File:</span> <span className="text-white ml-2 font-mono">{scanResult.filename}</span></div>
              <div><span className="text-gray-400">Language:</span> <span className="text-white ml-2 capitalize">{scanResult.language}</span></div>
              <div><span className="text-gray-400">Scanned:</span> <span className="text-white ml-2">{new Date(scanResult.scanned_at).toLocaleString()}</span></div>
              <div><span className="text-gray-400">AI Patches:</span> <span className="text-white ml-2">{patchResult?.ai_available ? "Yes (Gemma 4)" : "Verified Rules"}</span></div>
            </div>
          </div>

          {scanResult.vulnerabilities.length > 0 && (
            <div className="p-6 rounded-xl bg-gray-900 border border-gray-800">
              <h2 className="text-lg font-semibold text-white mb-4">Vulnerability Summary</h2>
              <div className="space-y-3">
                {scanResult.vulnerabilities.map((vuln, i) => (
                  <div key={vuln.id} className="flex items-start gap-3 p-3 rounded-lg bg-gray-950">
                    <span className="text-gray-500 text-sm font-mono w-6 flex-shrink-0">{i + 1}.</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <SeverityBadge severity={vuln.severity} />
                        <span className="text-white text-sm font-medium truncate">{vuln.title}</span>
                      </div>
                      <div className="text-gray-400 text-xs">
                        {vuln.rule_id} · Line {vuln.line_start} · {vuln.cwe_id || "No CWE"}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="text-center p-8 rounded-xl bg-gradient-to-br from-cyan-950/30 to-emerald-950/30 border border-cyan-500/20">
            <FileText className="w-12 h-12 text-cyan-400 mx-auto mb-4" />
            <h3 className="text-white font-semibold text-lg mb-2">Ready to download?</h3>
            <p className="text-gray-400 text-sm mb-4">
              Get an executive security report with vulnerability details, code snippets, and patch explanations.
            </p>
            <button
              onClick={handleDownload}
              disabled={isDownloading}
              className="inline-flex items-center gap-2 px-8 py-3 bg-cyan-500 hover:bg-cyan-400 text-gray-950 font-bold rounded-lg transition-all"
            >
              {isDownloading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Download className="w-5 h-5" />}
              Download Security Report
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
