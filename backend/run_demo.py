"""
PATCHPILOT CLI Demonstration
Runs the full scanning engine, patch generation, and re-scan validation.
"""
import asyncio
import os
import sys

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.scanners.engine import ScanEngine
from app.services.patch_generator import PatchGenerator
from app.services.report_generator import ReportGenerator

def main():
    demo_file = os.path.join(os.path.dirname(__file__), "demo", "vulnerable_example.py")
    with open(demo_file, "r", encoding="utf-8") as f:
        code = f.read()

    print("=" * 60)
    print("  PATCHPILOT: Find the flaw. Fix the code. Prove the patch.")
    print("=" * 60)
    print(f"\n[1] Scanning target: {os.path.basename(demo_file)} ({len(code.splitlines())} lines)...")

    engine = ScanEngine()
    scan_result = engine.run_scan(code, "python", "vulnerable_example.py")

    print(f"\n[+] Scan Complete! Flaws Identified: {scan_result.summary.total}")
    print(f"    - CRITICAL: {scan_result.summary.critical}")
    print(f"    - HIGH:     {scan_result.summary.high}")
    print(f"    - MEDIUM:   {scan_result.summary.medium}")
    print(f"    - LOW:      {scan_result.summary.low}")
    print(f"    - INFO:     {scan_result.summary.info}")
    print("\n" + "-" * 60)
    print("DETAILED VULNERABILITIES FOUND:")
    print("-" * 60)

    for i, v in enumerate(scan_result.vulnerabilities, 1):
        print(f"[{i:02d}] [{v.severity.upper():<8}] {v.title}")
        print(f"     CWE: {v.cwe_id or 'N/A'} | Rule: {v.rule_id} | Lines: {v.line_start}-{v.line_end}")
        snippet_first = v.code_snippet.strip().splitlines()[0] if v.code_snippet else ""
        print(f"     Code: {snippet_first[:65]}")
        rec_first = v.recommendation.strip().splitlines()[0] if v.recommendation else ""
        print(f"     Fix:  {rec_first[:65]}")
        print()

    print("=" * 60)
    print("[2] Generating Security Patches...")
    print("=" * 60)

    async def run_patches():
        patcher = PatchGenerator()
        patch_result = await patcher.generate_patches(code, scan_result.vulnerabilities, scan_result.scan_id)
        
        print(f"[+] Total Patches Prepared: {len(patch_result.patches)}")
        print(f"    AI Engine Status: {'Gemma 4 Online' if patch_result.ai_available else 'Rule-Based Engine (Fallback)'}")
        
        print("\n" + "-" * 60)
        print("SAMPLE GENERATED PATCHES:")
        print("-" * 60)
        for i, p in enumerate(patch_result.patches[:3], 1):
            vuln = next((v for v in scan_result.vulnerabilities if v.id == p.vulnerability_id), None)
            title = vuln.title if vuln else "Security Fix"
            print(f"Patch #{i}: {title} (Confidence: {int(p.confidence * 100)}%)")
            print(f"Explanation: {p.explanation.splitlines()[0][:70]}...")
            print()

        print("=" * 60)
        print("[3] Proving the Patch (Re-Scanning Patched Code)...")
        print("=" * 60)
        rescan = engine.run_scan(patch_result.patched_code_full, "python", "patched_code.py")
        
        print(f"[+] Re-scan Verification Results:")
        print(f"    Initial Total Flaws:  {scan_result.summary.total} (Critical: {scan_result.summary.critical})")
        print(f"    Post-Patch Flaws:     {rescan.summary.total} (Critical: {rescan.summary.critical})")
        resolved = scan_result.summary.total - rescan.summary.total
        print(f"    Total Flaws Resolved: {resolved} flaws eliminated automatically!")

        print("\n" + "=" * 60)
        print("[4] Generating Downloadable PDF Security Report...")
        print("=" * 60)
        reporter = ReportGenerator()
        pdf_bytes = reporter.generate_pdf(
            scan_id=scan_result.scan_id,
            original_code=code,
            patched_code=patch_result.patched_code_full,
            vulnerabilities=scan_result.vulnerabilities,
            patches=patch_result.patches,
        )
        report_path = os.path.join(os.path.dirname(__file__), "demo_security_report.pdf")
        with open(report_path, "wb") as f:
            f.write(pdf_bytes)
        print(f"[+] PDF Report successfully created: {report_path} ({len(pdf_bytes)} bytes)")
        print("\n[SUCCESS] All PATCHPILOT verification steps completed successfully!")

    asyncio.run(run_patches())

if __name__ == "__main__":
    main()
