import ast
import re
from typing import List
from app.models_core import Vulnerability
from app.scanners.base import BaseScanner

# Dangerous modules
DANGEROUS_MODULES = {
    "pickle": ("CWE-502", "high", "Importing pickle Module",
                "The pickle module deserializes arbitrary Python objects. "
                "Deserializing untrusted data can execute arbitrary code.",
                "Use json or another safe serialization format for external data."),
    "marshal": ("CWE-502", "high", "Importing marshal Module",
                 "marshal can deserialize Python bytecode. This is unsafe with untrusted data.",
                 "Avoid marshal for external data; use json instead."),
    "shelve": ("CWE-502", "medium", "Importing shelve Module",
                "shelve uses pickle internally and has the same deserialization risks.",
                "Use SQLite or another safe storage mechanism for untrusted data."),
    "ctypes": ("CWE-676", "medium", "Importing ctypes — Low-Level Memory Access",
                "ctypes provides C-level memory access. Misuse can lead to memory corruption.",
                "Limit ctypes usage to trusted, well-reviewed code paths."),
    "cffi": ("CWE-676", "medium", "Importing cffi — Foreign Function Interface",
              "cffi allows calling C functions directly, which can cause memory safety issues.",
              "Ensure all cffi calls are validated and not based on user input."),
}


class PythonStaticScanner(BaseScanner):
    """Detects Python-specific security misconfigurations via AST analysis."""

    @property
    def name(self) -> str:
        return "python_static"

    def scan(self, code: str, filename: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return vulns

        lines = code.splitlines()

        for node in ast.walk(tree):

            # ----------------------------------------------------------------
            # Dangerous imports
            # ----------------------------------------------------------------
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    if mod in DANGEROUS_MODULES:
                        cwe, sev, title, desc, rec = DANGEROUS_MODULES[mod]
                        snippet = self._get_snippet(lines, node.lineno)
                        vulns.append(Vulnerability(
                            rule_id=f"PY001_{mod.upper()}",
                            severity=sev,
                            title=title,
                            description=desc,
                            file=filename,
                            line_start=node.lineno,
                            line_end=getattr(node, "end_lineno", node.lineno),
                            code_snippet=snippet,
                            category="Dangerous Import",
                            cwe_id=cwe,
                            recommendation=rec,
                        ))

            if isinstance(node, ast.ImportFrom):
                mod = (node.module or "").split(".")[0]
                if mod in DANGEROUS_MODULES:
                    cwe, sev, title, desc, rec = DANGEROUS_MODULES[mod]
                    snippet = self._get_snippet(lines, node.lineno)
                    vulns.append(Vulnerability(
                        rule_id=f"PY001_{mod.upper()}",
                        severity=sev,
                        title=title,
                        description=desc,
                        file=filename,
                        line_start=node.lineno,
                        line_end=getattr(node, "end_lineno", node.lineno),
                        code_snippet=snippet,
                        category="Dangerous Import",
                        cwe_id=cwe,
                        recommendation=rec,
                    ))

            # ----------------------------------------------------------------
            # Flask debug=True  /  Django DEBUG=True
            # ----------------------------------------------------------------
            if isinstance(node, ast.keyword):
                if (
                    node.arg == "debug"
                    and isinstance(node.value, ast.Constant)
                    and node.value.value is True
                ):
                    snippet = self._get_snippet(lines, node.value.lineno)
                    vulns.append(Vulnerability(
                        rule_id="PY002",
                        severity="high",
                        title="Debug Mode Enabled in Application",
                        description=(
                            "debug=True exposes a full interactive debugger via the browser "
                            "and disables security protections. Never run with debug=True in production."
                        ),
                        file=filename,
                        line_start=node.value.lineno,
                        line_end=node.value.lineno,
                        code_snippet=snippet,
                        category="Security Misconfiguration",
                        cwe_id="CWE-94",
                        recommendation=(
                            "Set debug=False in production. Control via environment variable: "
                            "debug=os.environ.get('DEBUG', 'false').lower() == 'true'"
                        ),
                    ))

            # ----------------------------------------------------------------
            # Insecure random: import random + usage (not secrets)
            # ----------------------------------------------------------------
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "random":
                        snippet = self._get_snippet(lines, node.lineno)
                        vulns.append(Vulnerability(
                            rule_id="PY003",
                            severity="medium",
                            title="Use of Insecure random Module for Security Operations",
                            description=(
                                "The random module uses a predictable Mersenne Twister PRNG. "
                                "It must not be used for security-sensitive operations like "
                                "tokens, passwords, or session IDs."
                            ),
                            file=filename,
                            line_start=node.lineno,
                            line_end=node.lineno,
                            code_snippet=snippet,
                            category="Weak Cryptography",
                            cwe_id="CWE-338",
                            recommendation=(
                                "Use the secrets module for security tokens: "
                                "import secrets; token = secrets.token_urlsafe(32)"
                            ),
                        ))

            # ----------------------------------------------------------------
            # assert used for security checks
            # ----------------------------------------------------------------
            if isinstance(node, ast.Assert):
                # Only flag if assert appears to check user/auth-like conditions
                assert_src = ast.unparse(node) if hasattr(ast, "unparse") else ""
                security_words = ["user", "auth", "admin", "permission", "login", "token", "role"]
                if any(w in assert_src.lower() for w in security_words):
                    snippet = self._get_snippet(lines, node.lineno)
                    vulns.append(Vulnerability(
                        rule_id="PY004",
                        severity="high",
                        title="Security Check Using assert Statement",
                        description=(
                            "assert statements are removed when Python runs with optimization (-O). "
                            "Using assert for security checks (authentication, authorization) "
                            "can silently disable those checks in optimized deployments."
                        ),
                        file=filename,
                        line_start=node.lineno,
                        line_end=getattr(node, "end_lineno", node.lineno),
                        code_snippet=snippet,
                        category="Improper Authorization",
                        cwe_id="CWE-617",
                        recommendation=(
                            "Replace assert with an explicit if check that raises an appropriate "
                            "exception: if not condition: raise PermissionError('Access denied')"
                        ),
                    ))

            # ----------------------------------------------------------------
            # Binding to 0.0.0.0 explicitly (informational)
            # ----------------------------------------------------------------
            if isinstance(node, ast.Constant) and node.value == "0.0.0.0":
                snippet = self._get_snippet(lines, node.lineno)
                vulns.append(Vulnerability(
                    rule_id="PY005",
                    severity="info",
                    title="Server Bound to All Interfaces (0.0.0.0)",
                    description=(
                        "Binding to 0.0.0.0 makes the service accessible from all network interfaces. "
                        "In a production environment, restrict to a specific interface unless intentional."
                    ),
                    file=filename,
                    line_start=node.lineno,
                    line_end=node.lineno,
                    code_snippet=snippet,
                    category="Security Misconfiguration",
                    cwe_id="CWE-200",
                    recommendation=(
                        "In production, bind to a specific IP (e.g., 127.0.0.1) unless "
                        "an external load balancer or proxy handles incoming traffic."
                    ),
                ))

        return vulns

    def _get_snippet(self, lines: List[str], lineno: int, context: int = 2) -> str:
        start = max(0, lineno - 1 - context)
        end = min(len(lines), lineno + context)
        return "\n".join(lines[start:end])
