import uuid
from typing import List
from app.models_core import ScanResult, ScanSummary, Vulnerability
from app.scanners.sql_injection import SQLInjectionScanner
from app.scanners.hardcoded_creds import HardcodedCredsScanner
from app.scanners.unsafe_eval import UnsafeEvalScanner
from app.scanners.python_static import PythonStaticScanner
from app.scanners.base import BaseScanner


class ScanEngine:
    """Orchestrates all security scanners and aggregates results."""

    def __init__(self):
        self._scanners: List[BaseScanner] = [
            SQLInjectionScanner(),
            HardcodedCredsScanner(),
            UnsafeEvalScanner(),
            PythonStaticScanner(),
        ]

    def run_scan(self, code: str, language: str, filename: str) -> ScanResult:
        all_vulns: List[Vulnerability] = []

        for scanner in self._scanners:
            try:
                found = scanner.scan(code, filename)
                all_vulns.extend(found)
            except Exception as exc:
                # One scanner failing must not break the whole scan
                import logging
                logging.getLogger("patchpilot").warning(
                    f"Scanner {scanner.name} raised an error: {exc}"
                )

        # Deduplicate by (rule_id, line_start)
        seen = set()
        unique_vulns: List[Vulnerability] = []
        for v in all_vulns:
            key = (v.rule_id, v.line_start)
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)

        # Sort: critical first
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        unique_vulns.sort(key=lambda v: severity_order.get(v.severity, 99))

        summary = ScanSummary(
            total=len(unique_vulns),
            critical=sum(1 for v in unique_vulns if v.severity == "critical"),
            high=sum(1 for v in unique_vulns if v.severity == "high"),
            medium=sum(1 for v in unique_vulns if v.severity == "medium"),
            low=sum(1 for v in unique_vulns if v.severity == "low"),
            info=sum(1 for v in unique_vulns if v.severity == "info"),
        )

        return ScanResult(
            scan_id=str(uuid.uuid4()),
            vulnerabilities=unique_vulns,
            summary=summary,
            language=language,
            filename=filename,
        )
