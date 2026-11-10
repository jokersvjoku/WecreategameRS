import Link from "next/link";
import { Shield, Github, ExternalLink } from "lucide-react";

export default function Footer() {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="border-t border-gray-800 bg-gray-950" aria-label="Site footer">
      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
          {/* Brand */}
          <div className="flex flex-col gap-3">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center">
                <Shield className="w-3.5 h-3.5 text-cyan-400" />
              </div>
              <span className="font-bold text-base">
                <span className="text-cyan-400">PATCH</span>
                <span className="text-white">PILOT</span>
              </span>
            </div>
            <p className="text-gray-500 text-xs leading-relaxed max-w-xs">
              Python static security scanner. Detect vulnerabilities, generate AI patches, and verify the fix. No backend required on GitHub Pages.
            </p>
          </div>

          {/* Navigation */}
          <div>
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Navigation</h3>
            <ul className="space-y-2">
              {[
                { href: "/", label: "Home" },
                { href: "/scanner", label: "Code Scanner" },
                { href: "/dashboard", label: "Dashboard" },
                { href: "/scanner?demo=true", label: "Live Demo" },
              ].map(({ href, label }) => (
                <li key={href}>
                  <Link
                    href={href}
                    className="text-sm text-gray-500 hover:text-gray-300 transition-colors"
                  >
                    {label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Project */}
          <div>
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Project</h3>
            <ul className="space-y-2">
              <li>
                <a
                  href="https://github.com/Swastikvitthare/PatchPilot"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-300 transition-colors"
                >
                  <Github className="w-3.5 h-3.5" aria-hidden="true" />
                  Source Code
                  <ExternalLink className="w-3 h-3" aria-hidden="true" />
                </a>
              </li>
              <li>
                <a
                  href="https://github.com/Swastikvitthare/PatchPilot/blob/main/docs/API.md"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-300 transition-colors"
                >
                  <ExternalLink className="w-3 h-3" aria-hidden="true" />
                  API Documentation
                </a>
              </li>
              <li>
                <a
                  href="https://github.com/Swastikvitthare/PatchPilot/blob/main/docs/DEPLOYMENT.md"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-300 transition-colors"
                >
                  <ExternalLink className="w-3 h-3" aria-hidden="true" />
                  Deployment Guide
                </a>
              </li>
            </ul>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-5 border-t border-gray-800/60">
          <p className="text-xs text-gray-600">
            © {currentYear} PATCHPILOT. Built by{" "}
            <a
              href="https://github.com/Swastikvitthare"
              target="_blank"
              rel="noopener noreferrer"
              className="text-gray-500 hover:text-gray-400 transition-colors"
            >
              Swastik Vitthare
            </a>
            .
          </p>

          <div className="flex items-center gap-1.5 px-3 py-1 rounded-full border border-gray-800 bg-gray-900/60">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" aria-hidden="true" />
            <span className="text-xs text-gray-500">Powered by</span>
            <span className="text-xs text-emerald-400 font-semibold">Google Gemma 4</span>
            <span className="text-gray-700 text-xs">·</span>
            <span className="text-xs text-gray-500">DigitalOcean Gradient</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
