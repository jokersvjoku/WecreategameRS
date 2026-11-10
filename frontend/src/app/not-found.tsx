import Link from "next/link";
import { Shield, AlertTriangle, Home, Search } from "lucide-react";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Page Not Found | PATCHPILOT",
  description: "The page you are looking for does not exist.",
};

export default function NotFound() {
  return (
    <div className="min-h-screen cyber-grid flex items-center justify-center px-4">
      <div className="max-w-lg w-full text-center">
        {/* Icon */}
        <div className="w-20 h-20 rounded-2xl bg-red-500/10 border border-red-500/30 flex items-center justify-center mx-auto mb-6">
          <AlertTriangle className="w-10 h-10 text-red-400" />
        </div>

        {/* Error code */}
        <div className="font-mono text-8xl font-black text-transparent bg-clip-text bg-gradient-to-r from-red-400 to-orange-400 mb-2">
          404
        </div>

        <h1 className="text-2xl font-bold text-white mb-3">Page Not Found</h1>
        <p className="text-gray-400 mb-8 leading-relaxed">
          This page does not exist or has been moved. If you arrived here from a
          direct link, the scan result may have expired from session storage.
        </p>

        {/* Actions */}
        <div className="flex flex-col sm:flex-row gap-3 justify-center">
          <Link
            href="/"
            className="inline-flex items-center justify-center gap-2 px-6 py-3 bg-gray-800 hover:bg-gray-700 text-white font-semibold rounded-xl border border-gray-700 hover:border-gray-600 transition-all"
          >
            <Home className="w-4 h-4" />
            Go Home
          </Link>
          <Link
            href="/scanner"
            className="inline-flex items-center justify-center gap-2 px-6 py-3 bg-cyan-500 hover:bg-cyan-400 text-gray-950 font-bold rounded-xl transition-all glow-cyan"
          >
            <Search className="w-4 h-4" />
            Start a New Scan
          </Link>
        </div>

        {/* Hint */}
        <div className="mt-10 p-4 rounded-xl bg-gray-900/60 border border-gray-800 text-left text-sm">
          <p className="text-gray-400 font-mono text-xs mb-2 text-cyan-400">{"// PATCHPILOT — Debug info"}</p>
          <p className="text-gray-500 text-xs font-mono">
            Requested path not found in static export.<br />
            Dynamic scan IDs require active browser session storage.<br />
            Navigate from <span className="text-cyan-400">/scanner</span> to preserve scan context.
          </p>
        </div>
      </div>
    </div>
  );
}
