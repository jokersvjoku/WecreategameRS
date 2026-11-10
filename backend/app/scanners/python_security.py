"""Broader Python security scanner — miscellaneous best-practice checks."""

from __future__ import annotations

import ast
import re
from typing import List

from app.models.schemas import Severity, VulnerabilityDetail
from app.scanners.base import BaseScanner


def _source_lines(code: str) -> List[str]:
    return code.splitlines()


class _PythonSecurityVisitor(ast.NodeVisitor):
    """AST visitor for general Python security anti-patterns."""

    def __init__(self, code: str) -> None:
        self.code = code
        self.lines = _source_lines(code)
        self.findings: List[VulnerabilityDetail] = []

    def _snippet(self, lineno: int) -> str:
        idx = lineno - 1
        start = max(0, idx - 1)
        end = min(len(self.lines), idx + 2)
        return "\n".join(self.lines[start:end])

    def _add(
        self,
        lineno: int,
        rule_id: str,
        severity: Severity,
        title: str,
        description: str,
        cwe_id: str | None = None,
    ) -> None:
        self.findings.append(
            VulnerabilityDetail(
                rule_id=rule_id,
                severity=severity,
                title=title,
                description=description,
                line_number=lineno,
                snippet=self._snippet(lineno),
                cwe_id=cwe_id,
            )
        )

    # ---- visitors --------------------------------------------------------

    def visit_Assert(self, node: ast.Assert) -> None:
        """Assert statements are stripped when Python is run with -O."""
        self._add(
            node.lineno,
            "PYSEC-001",
            Severity.MEDIUM,
            "Assert used for validation",
            "assert statements are removed when Python is run with -O "
            "(optimise). Do not rely on them for security checks — use "
            "explicit if/raise instead.",
            "CWE-617",
        )
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Bare except or except BaseException catches everything."""
        if node.type is None:
            self._add(
                node.lineno,
                "PYSEC-002",
                Severity.MEDIUM,
                "Bare except clause",
                "A bare 'except:' catches all exceptions including "
                "KeyboardInterrupt and SystemExit. Use 'except Exception:' "
                "to avoid swallowing critical signals.",
                "CWE-396",
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: C901
        fname = self._func_name(node)
        if fname is None:
            self.generic_visit(node)
            return

        # --- Weak hashing ---
        if fname in (
            "hashlib.md5",
            "hashlib.sha1",
            "md5.new",
            "sha.new",
        ):
            self._add(
                node.lineno,
                "PYSEC-003",
                Severity.MEDIUM,
                f"Weak hash function: {fname}",
                f"{fname} is considered cryptographically broken. "
                "Use SHA-256 or stronger for security purposes.",
                "CWE-328",
            )

        # --- Binding to 0.0.0.0 ---
        if fname in ("bind", "socket.bind") or (
            isinstance(node.func, ast.Attribute) and node.func.attr == "bind"
        ):
            for arg in node.args:
                if isinstance(arg, ast.Tuple) and arg.elts:
                    first = arg.elts[0]
                    if isinstance(first, ast.Constant) and first.value == "0.0.0.0":
                        self._add(
                            node.lineno,
                            "PYSEC-004",
                            Severity.MEDIUM,
                            "Binding to 0.0.0.0",
                            "Binding a socket to 0.0.0.0 exposes the service on "
                            "all network interfaces. Bind to 127.0.0.1 or a "
                            "specific interface unless public access is intended.",
                            "CWE-200",
                        )

        # --- Insecure random ---
        if fname in ("random.random", "random.randint", "random.choice",
                      "random.randrange", "random.getrandbits"):
            self._add(
                node.lineno,
                "PYSEC-006",
                Severity.MEDIUM,
                f"Insecure random: {fname}",
                "The random module is not cryptographically secure. "
                "Use the secrets module for tokens, passwords, or "
                "security-sensitive randomness.",
                "CWE-330",
            )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Detect DEBUG = True patterns."""
        for target in node.targets:
            name = None
            if isinstance(target, ast.Name):
                name = target.id
            elif isinstance(target, ast.Attribute):
                name = target.attr
            if name and name.upper() == "DEBUG":
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    self._add(
                        node.lineno,
                        "PYSEC-005",
                        Severity.MEDIUM,
                        "Debug mode enabled",
                        "DEBUG is set to True. Ensure debug mode is disabled "
                        "in production to avoid leaking sensitive information.",
                        "CWE-215",
                    )
        self.generic_visit(node)

    # ---- helpers ---------------------------------------------------------

    @staticmethod
    def _func_name(node: ast.Call) -> str | None:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            parts: list[str] = [func.attr]
            value = func.value
            while isinstance(value, ast.Attribute):
                parts.append(value.attr)
                value = value.value
            if isinstance(value, ast.Name):
                parts.append(value.id)
            return ".".join(reversed(parts))
        return None


class _RegexPythonSecurityScanner:
    """Regex-based checks that complement the AST visitor."""

    _IP_PATTERN = re.compile(
        r"""(['"])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\1"""
    )
    _EXCLUDE_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "0.0.0.0"}

    def scan(self, code: str) -> List[VulnerabilityDetail]:
        findings: List[VulnerabilityDetail] = []
        lines = _source_lines(code)
        for idx, line in enumerate(lines, start=1):
            # Hardcoded IP addresses
            for m in self._IP_PATTERN.finditer(line):
                ip = m.group(2)
                if ip not in self._EXCLUDE_IPS:
                    findings.append(
                        VulnerabilityDetail(
                            rule_id="PYSEC-007",
                            severity=Severity.LOW,
                            title="Hardcoded IP address",
                            description=(
                                f"The IP address {ip} is hardcoded. "
                                "Use configuration files or environment variables."
                            ),
                            line_number=idx,
                            snippet=line.strip(),
                            cwe_id="CWE-200",
                        )
                    )
        return findings


class PythonSecurityScanner(BaseScanner):
    """Broad Python security checks — AST + regex."""

    def scan(self, code: str, filename: str) -> List[VulnerabilityDetail]:
        findings: List[VulnerabilityDetail] = []

        try:
            tree = ast.parse(code, filename=filename or "<string>")
            visitor = _PythonSecurityVisitor(code)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            pass

        regex_scanner = _RegexPythonSecurityScanner()
        regex_findings = regex_scanner.scan(code)

        existing = {(f.rule_id, f.line_number) for f in findings}
        for rf in regex_findings:
            if (rf.rule_id, rf.line_number) not in existing:
                findings.append(rf)

        return findings
