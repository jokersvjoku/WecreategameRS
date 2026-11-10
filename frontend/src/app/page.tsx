import Link from "next/link";
import {
  Shield,
  Search,
  Key,
  Zap,
  Bot,
  CheckCircle,
  ArrowRight,
  Code2,
  FileSearch,
  Wrench,
  FileText,
} from "lucide-react";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "PATCHPILOT — Find the flaw. Fix the code. Prove the patch.",
};

const features = [
  {
    icon: Code2,
    title: "Code Editor & File Upload",
    description:
      "Paste Python directly or upload a .py file. The lightweight textarea editor works on every browser with no CDN dependency.",
    color: "cyan",
  },
  {
    icon: Search,
    title: "SQL Injection Detection (CWE-89)",
    description:
      "Detects f-string interpolation, string concatenation, .format() and % operator patterns inside SQL query strings.",
    color: "orange",
  },
  {
    icon: Key,
    title: "Credential Leak Detection (CWE-798)",
    description:
      "Identifies hardcoded passwords, AWS access keys, API tokens, and generic secrets assigned as string literals.",
    color: "red",
  },
  {
    icon: Zap,
    title: "Unsafe Execution (CWE-95 / CWE-78)",
    description:
      "Flags eval(), exec(), os.system(), subprocess with shell=True, and insecure pickle.loads() deserialization.",
    color: "yellow",
  },
  {
    icon: Bot,
    title: "Gemma 4 AI Patch Generation",
    description:
      "Google Gemma 4 explains each vulnerability in plain language and generates a targeted secure replacement for every finding.",
    color: "emerald",
  },
  {
    icon: CheckCircle,
    title: "Proof-of-Fix Verification",
    description:
      "Re-scan the patched code with the same engine to mathematically prove that the vulnerability is eliminated, not just claimed fixed.",
    color: "emerald",
  },
];

const steps = [
  {
    number: "01",
    icon: Code2,
    title: "Paste or Upload Code",
    desc: "Use the built-in editor or drag-and-drop a .py file up to 512 KB.",
  },
  {
    number: "02",
    icon: FileSearch,
    title: "Scan for Vulnerabilities",
    desc: "AST-based pattern matching analyses your code without executing a single line.",
  },
  {
    number: "03",
    icon: Wrench,
    title: "Generate AI Patches",
    desc: "Gemma 4 explains each issue and produces a corrected version with confidence scores.",
  },
  {
    number: "04",
    icon: FileText,
    title: "Download Audit Report",
    desc: "Get a plain-text security report with all findings and patches for your records.",
  },
];

const colorMap: Record<string, string> = {
  cyan: "text-cyan-400 bg-cyan-400/10 border-cyan-400/20",
  orange: "text-orange-400 bg-orange-400/10 border-orange-400/20",
  red: "text-red-400 bg-red-400/10 border-red-400/20",
  yellow: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  emerald: "text-emerald-400 bg-emerald-400/10 border-emerald-400/20",
};

export default function LandingPage() {
  return (
    <div className="cyber-grid min-h-screen overflow-x-hidden">
      {/* ── Hero ── */}
      <section className="relative pt-20 pb-16 px-4" aria-labelledby="hero-heading">
        <div className="max-w-4xl mx-auto text-center">
          {/* Badge */}
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 text-sm font-mono mb-8">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" aria-hidden="true" />
            Powered by Google Gemma 4 · DigitalOcean Gradient
          </div>

          {/* Title */}
          <h1
            id="hero-heading"
            className="text-5xl sm:text-6xl md:text-8xl font-black tracking-tighter mb-6 leading-none"
          >
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-emerald-400">
              PATCH
            </span>
            <span className="text-white">PILOT</span>
          </h1>

          <p className="text-lg md:text-2xl text-gray-400 font-mono mb-3">
            Find the flaw.{" "}
            <span className="text-cyan-400">Fix the code.</span>{" "}
            <span className="text-emerald-400">Prove the patch.</span>
          </p>

          <p className="text-gray-500 max-w-2xl mx-auto mb-10 text-base md:text-lg leading-relaxed">
            AI-powered static security scanner for Python. Detect SQL injection, hardcoded
            credentials, unsafe eval, and more — then let Gemma 4 fix it and re-scan to
            prove the vulnerability is gone.
          </p>

          <div className="flex flex-col sm:flex-row gap-3 justify-center">
            <Link
              href="/scanner"
              className="inline-flex items-center justify-center gap-2 px-7 py-3.5 bg-cyan-500 hover:bg-cyan-400 active:bg-cyan-600 text-gray-950 font-bold rounded-xl transition-all glow-cyan text-base focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:ring-offset-2 focus:ring-offset-gray-950"
            >
              <Shield className="w-5 h-5" aria-hidden="true" />
              Launch Scanner
              <ArrowRight className="w-5 h-5" aria-hidden="true" />
            </Link>
            <Link
              href="/scanner?demo=true"
              className="inline-flex items-center justify-center gap-2 px-7 py-3.5 border border-cyan-500/40 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 hover:text-cyan-300 font-semibold rounded-xl transition-all text-base"
            >
              <Zap className="w-5 h-5" aria-hidden="true" />
              Live Interactive Demo
            </Link>
          </div>
        </div>

        {/* Background glow — decorative */}
        <div
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] rounded-full bg-cyan-500/4 blur-3xl pointer-events-none"
          aria-hidden="true"
        />
      </section>

      {/* ── Features ── */}
      <section className="py-16 px-4 bg-gray-900/30" aria-labelledby="features-heading">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <h2 id="features-heading" className="text-3xl md:text-4xl font-bold text-white mb-3">
              Everything you need to{" "}
              <span className="text-cyan-400">secure your code</span>
            </h2>
            <p className="text-gray-400 text-base max-w-2xl mx-auto">
              Six security modules working together to find and eliminate vulnerabilities —
              works entirely in the browser, no backend required.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
            {features.map((feature) => {
              const Icon = feature.icon;
              const cls = colorMap[feature.color];
              return (
                <div
                  key={feature.title}
                  className="p-6 rounded-xl bg-gray-900 border border-gray-800 hover:border-gray-700 transition-all duration-200"
                >
                  <div className={`w-11 h-11 rounded-xl border flex items-center justify-center mb-4 ${cls}`}>
                    <Icon className="w-5 h-5" aria-hidden="true" />
                  </div>
                  <h3 className="text-base font-semibold text-white mb-2">{feature.title}</h3>
                  <p className="text-gray-400 text-sm leading-relaxed">{feature.description}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* ── How It Works ── */}
      <section className="py-16 px-4" aria-labelledby="how-heading">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-12">
            <h2 id="how-heading" className="text-3xl md:text-4xl font-bold text-white mb-3">
              How PATCHPILOT works
            </h2>
            <p className="text-gray-400 text-base">Four steps from vulnerable code to a verified, patched result.</p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            {steps.map((step, i) => {
              const Icon = step.icon;
              return (
                <div key={step.number} className="relative text-center">
                  {i < steps.length - 1 && (
                    <div
                      className="hidden lg:block absolute top-8 left-1/2 w-full h-px bg-gradient-to-r from-cyan-500/30 to-transparent"
                      aria-hidden="true"
                    />
                  )}
                  <div className="relative z-10 inline-flex flex-col items-center">
                    <div className="w-16 h-16 rounded-full bg-gray-900 border-2 border-cyan-500/40 flex items-center justify-center mb-4">
                      <Icon className="w-7 h-7 text-cyan-400" aria-hidden="true" />
                    </div>
                    <span className="font-mono text-xs text-cyan-500 mb-2" aria-hidden="true">{step.number}</span>
                    <h3 className="text-white font-semibold mb-2 text-sm">{step.title}</h3>
                    <p className="text-gray-400 text-sm leading-relaxed">{step.desc}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* ── CTA ── */}
      <section className="py-16 px-4 bg-gradient-to-b from-transparent to-cyan-950/10" aria-labelledby="cta-heading">
        <div className="max-w-2xl mx-auto text-center">
          <Shield className="w-14 h-14 text-cyan-400 mx-auto mb-5" aria-hidden="true" />
          <h2 id="cta-heading" className="text-3xl md:text-4xl font-bold text-white mb-3">
            Ready to secure your code?
          </h2>
          <p className="text-gray-400 text-base mb-8 leading-relaxed">
            No account required. Paste your Python code and get a full vulnerability report in seconds, entirely in your browser.
          </p>
          <Link
            href="/scanner"
            className="inline-flex items-center gap-3 px-8 py-4 bg-gradient-to-r from-cyan-500 to-emerald-500 text-gray-950 font-bold rounded-2xl text-base transition-all hover:opacity-90 active:opacity-80 focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:ring-offset-2 focus:ring-offset-gray-950"
          >
            <Shield className="w-5 h-5" aria-hidden="true" />
            Scan Your Code Now
            <ArrowRight className="w-5 h-5" aria-hidden="true" />
          </Link>
        </div>
      </section>
    </div>
  );
}
