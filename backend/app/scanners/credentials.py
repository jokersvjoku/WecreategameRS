"""Scanner for hardcoded credentials and secrets (CWE-798)."""

from __future__ import annotations

import ast
import re
from typing import List

from app.models.schemas import Severity, VulnerabilityDetail
from app.scanners.base import BaseScanner

# Variable / key names that commonly hold secrets
_SECRET_NAMES = re.compile(
    r"(password|passwd|secret|api_key|apikey|access_key|auth_token|"
    r"token|private_key|secret_key|client_secret|db_password|"
    r"database_password|mysql_pwd|jwt_secret|encryption_key)",
    re.IGNORECASE,
)

# AWS access key pattern  (starts with AKIA)
_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")

# Generic long alphanumeric tokens  (20+ chars)
_GENERIC_TOKEN = re.compile(r"[A-Za-z0-9/+=]{20,}")


def _source_lines(code: str) -> List[str]:
    return code.splitlines()


class _CredentialASTVisitor(ast.NodeVisitor):
    """Walk the AST to find assignments of string literals to secret-looking names."""

    def __init__(self, code: str) -> None:
        self.code = code
        self.lines = _source_lines(code)
        self.findings: List[VulnerabilityDetail] = []

    def _snippet(self, lineno: int) -> str:
        idx = lineno - 1
        start = max(0, idx - 1)
        end = min(len(self.lines), idx + 2)
        return "\n".join(self.lines[start:end])

    def _add(self, lineno: int, name: str, value: str) -> None:
        masked = value[:4] + "****" if len(value) > 4 else "****"
        self.findings.append(
            VulnerabilityDetail(
                rule_id="CRED-001",
                severity=Severity.CRITICAL,
                title=f"Hardcoded credential: {name}",
                description=(
                    f"The variable '{name}' is assigned a string literal that "
                    f"appears to be a credential (value starts with '{masked}'). "
                    "Credentials must never be stored in source code. "
                    "Use environment variables or a secrets manager."
                ),
                line_number=lineno,
                snippet=self._snippet(lineno),
                cwe_id="CWE-798",
            )
        )

    # ---- visitors --------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            value_str = node.value.value
            if not value_str or len(value_str) < 2:
                self.generic_visit(node)
                return
            for target in node.targets:
                name = self._target_name(target)
                if name and _SECRET_NAMES.search(name):
                    self._add(node.lineno, name, value_str)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if (
            node.value
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            value_str = node.value.value
            if not value_str or len(value_str) < 2:
                self.generic_visit(node)
                return
            name = self._target_name(node.target)
            if name and _SECRET_NAMES.search(name):
                self._add(node.lineno, name, value_str)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        """Detect dictionary literals with secret-looking keys mapped to string values."""
        for key, val in zip(node.keys, node.values):
            if (
                key is not None
                and isinstance(key, ast.Constant)
                and isinstance(key.value, str)
                and isinstance(val, ast.Constant)
                and isinstance(val.value, str)
            ):
                if _SECRET_NAMES.search(key.value) and len(val.value) >= 2:
                    self._add(
                        getattr(key, "lineno", 0),
                        key.value,
                        val.value,
                    )
        self.generic_visit(node)

    # ---- helpers ---------------------------------------------------------

    @staticmethod
    def _target_name(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None


class _CredentialRegexScanner:
    """Catch patterns the AST cannot see (comments, inline strings)."""

    def scan(self, code: str) -> List[VulnerabilityDetail]:
        findings: List[VulnerabilityDetail] = []
        lines = _source_lines(code)

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()

            # --- AWS access key anywhere on the line ---
            if _AWS_KEY.search(line):
                findings.append(
                    VulnerabilityDetail(
                        rule_id="CRED-002",
                        severity=Severity.CRITICAL,
                        title="AWS access key detected",
                        description=(
                            "A string matching the AWS access key format (AKIA…) "
                            "was found. Rotate this key immediately and remove "
                            "it from source code."
                        ),
                        line_number=idx,
                        snippet=line.strip(),
                        cwe_id="CWE-798",
                    )
                )

            # --- comment containing long token-like value after = or : ---
            if stripped.startswith("#"):
                match = re.search(r"[=:]\s*([A-Za-z0-9/+=]{20,})", stripped)
                if match:
                    findings.append(
                        VulnerabilityDetail(
                            rule_id="CRED-003",
                            severity=Severity.HIGH,
                            title="Possible credential in comment",
                            description=(
                                "A comment contains a long alphanumeric string "
                                "that may be a token or key. Remove it from "
                                "source code."
                            ),
                            line_number=idx,
                            snippet=stripped,
                            cwe_id="CWE-798",
                        )
                    )

        return findings


class HardcodedCredentialScanner(BaseScanner):
    """Detect hardcoded credentials, API keys, and secrets."""

    def scan(self, code: str, filename: str) -> List[VulnerabilityDetail]:
        findings: List[VulnerabilityDetail] = []

        # AST-based detection
        try:
            tree = ast.parse(code, filename=filename or "<string>")
            visitor = _CredentialASTVisitor(code)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            pass

        # Regex-based detection
        regex_scanner = _CredentialRegexScanner()
        regex_findings = regex_scanner.scan(code)

        existing = {(f.rule_id, f.line_number) for f in findings}
        for rf in regex_findings:
            if (rf.rule_id, rf.line_number) not in existing:
                findings.append(rf)
                existing.add((rf.rule_id, rf.line_number))

        return findings
