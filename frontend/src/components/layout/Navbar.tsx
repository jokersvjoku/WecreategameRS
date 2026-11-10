"use client";
import Link from "next/link";
import { useState } from "react";
import { Shield, Github, LayoutDashboard, Search, Menu, X } from "lucide-react";

export default function Navbar() {
  const [mobileOpen, setMobileOpen] = useState(false);

  const navLinks = [
    { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
    { href: "/scanner", label: "Scanner", icon: Search },
  ];

  return (
    <nav className="sticky top-0 z-50 border-b border-gray-800 bg-gray-950/95 backdrop-blur-md" aria-label="Primary navigation">
      <div className="max-w-7xl mx-auto px-4">
        <div className="flex items-center h-16 gap-6">
          {/* Logo */}
          <Link
            href="/"
            className="flex items-center gap-2.5 group shrink-0"
            aria-label="PATCHPILOT — Home"
          >
            <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center group-hover:bg-cyan-500/30 transition-all">
              <Shield className="text-cyan-400" style={{ width: "18px", height: "18px" }} />
            </div>
            <span className="font-black text-lg tracking-tight">
              <span className="text-cyan-400">PATCH</span>
              <span className="text-white">PILOT</span>
            </span>
          </Link>

          {/* Desktop Nav links */}
          <div className="hidden md:flex items-center gap-1 ml-2" role="list">
            {navLinks.map(({ href, label, icon: Icon }) => (
              <Link
                key={href}
                href={href}
                className="flex items-center gap-2 px-3 py-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition-all text-sm"
                role="listitem"
              >
                <Icon className="w-4 h-4" aria-hidden="true" />
                {label}
              </Link>
            ))}
          </div>

          {/* Right side */}
          <div className="ml-auto flex items-center gap-3">
            <a
              href="https://github.com/Swastikvitthare/PatchPilot"
              target="_blank"
              rel="noopener noreferrer"
              className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg text-gray-400 hover:text-white border border-gray-800 hover:border-gray-700 transition-all text-sm"
              aria-label="View source code on GitHub"
            >
              <Github className="w-4 h-4" aria-hidden="true" />
              <span>GitHub</span>
            </a>
            <Link
              href="/scanner"
              className="hidden sm:flex items-center gap-2 px-4 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-gray-950 font-semibold rounded-lg transition-all text-sm focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:ring-offset-2 focus:ring-offset-gray-950"
            >
              <Search className="w-3.5 h-3.5" aria-hidden="true" />
              Scan Code
            </Link>

            {/* Mobile hamburger */}
            <button
              onClick={() => setMobileOpen((o) => !o)}
              className="md:hidden p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition-all focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              aria-label={mobileOpen ? "Close menu" : "Open menu"}
              aria-expanded={mobileOpen}
            >
              {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile menu */}
      {mobileOpen && (
        <div
          className="md:hidden border-t border-gray-800 bg-gray-950/98 backdrop-blur-md"
          role="navigation"
          aria-label="Mobile navigation"
        >
          <div className="max-w-7xl mx-auto px-4 py-3 space-y-1">
            {navLinks.map(({ href, label, icon: Icon }) => (
              <Link
                key={href}
                href={href}
                onClick={() => setMobileOpen(false)}
                className="flex items-center gap-3 px-4 py-3 rounded-xl text-gray-400 hover:text-white hover:bg-gray-800 transition-all"
              >
                <Icon className="w-5 h-5" aria-hidden="true" />
                <span className="font-medium">{label}</span>
              </Link>
            ))}
            <div className="pt-2 pb-1 border-t border-gray-800 flex flex-col gap-2">
              <Link
                href="/scanner"
                onClick={() => setMobileOpen(false)}
                className="flex items-center justify-center gap-2 px-4 py-3 bg-cyan-500 hover:bg-cyan-400 text-gray-950 font-bold rounded-xl transition-all"
              >
                <Search className="w-4 h-4" aria-hidden="true" />
                Scan Code Now
              </Link>
              <a
                href="https://github.com/Swastikvitthare/PatchPilot"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-center gap-2 px-4 py-3 border border-gray-700 rounded-xl text-gray-400 hover:text-white hover:border-gray-600 transition-all"
              >
                <Github className="w-4 h-4" aria-hidden="true" />
                View on GitHub
              </a>
            </div>
          </div>
        </div>
      )}
    </nav>
  );
}
