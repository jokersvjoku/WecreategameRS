"use client";
import React, { useState } from "react";
import { Check, Copy, Code2, ShieldCheck, ArrowRight } from "lucide-react";

interface DiffViewerProps {
  original: string;
  patched: string;
}

export default function DiffViewer({ original, patched }: DiffViewerProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(patched);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const originalLines = (original || "").split("\n");
  const patchedLines = (patched || "").split("\n");

  return (
    <div className="space-y-4">
      {/* Action Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-gray-900/80 rounded-xl border border-gray-800">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
          <span className="text-sm font-semibold text-white">Side-by-Side Patch Comparison</span>
          <span className="text-xs text-gray-500 font-mono">Original vs. Gemma 4 Fix</span>
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-mono transition-all"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-cyan-400" />}
          <span>{copied ? "Copied!" : "Copy Patched Code"}</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Original (Vulnerable) */}
        <div>
          <div className="flex items-center justify-between px-3 py-2 bg-red-950/30 border border-b-0 border-red-500/30 rounded-t-xl text-xs font-mono text-red-400">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse" />
              <span className="font-bold">BEFORE (Vulnerable Code)</span>
            </div>
            <span className="text-red-400/80">{originalLines.length} lines</span>
          </div>
          <div className="rounded-b-xl border border-red-500/30 bg-gray-950 overflow-x-auto max-h-[460px] overflow-y-auto font-mono text-xs p-3">
            {originalLines.map((line, idx) => (
              <div key={idx} className="flex hover:bg-red-500/10 py-0.5 px-1 rounded">
                <span className="select-none text-gray-600 text-right w-8 pr-3 shrink-0">{idx + 1}</span>
                <span className={`text-gray-300 whitespace-pre ${/password|eval|os\.system|exec|SELECT.*\+|debug\s*=\s*True/i.test(line) ? "text-red-300 bg-red-900/30 font-semibold px-1 rounded" : ""}`}>
                  {line || " "}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Patched (Secure) */}
        <div>
          <div className="flex items-center justify-between px-3 py-2 bg-emerald-950/30 border border-b-0 border-emerald-500/30 rounded-t-xl text-xs font-mono text-emerald-400">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
              <span className="font-bold">AFTER (Patched & Verified)</span>
            </div>
            <span className="text-emerald-400/80">{patchedLines.length} lines</span>
          </div>
          <div className="rounded-b-xl border border-emerald-500/30 bg-gray-950 overflow-x-auto max-h-[460px] overflow-y-auto font-mono text-xs p-3">
            {patchedLines.map((line, idx) => (
              <div key={idx} className="flex hover:bg-emerald-500/10 py-0.5 px-1 rounded">
                <span className="select-none text-gray-600 text-right w-8 pr-3 shrink-0">{idx + 1}</span>
                <span className={`text-gray-300 whitespace-pre ${/ast\.literal_eval|subprocess\.run|os\.environ|debug\s*=\s*os|PATCHPILOT|# Loaded securely/i.test(line) ? "text-emerald-300 bg-emerald-900/30 font-semibold px-1 rounded" : ""}`}>
                  {line || " "}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
