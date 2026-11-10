import ast
import re
from typing import List
from app.models_core import Vulnerability
from app.scanners.base import BaseScanner

# SQL keywords that indicate a query string
SQL_KEYWORDS = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|REPLACE|EXEC|EXECUTE|UNION|FROM|WHERE)\b",
    re.IGNORECASE,
)


class SQLInjectionScanner(BaseScanner):
    """Detects SQL injection vulnerabilities via AST analysis."""

    @property
    def name(self) -> str:
        return "sql_injection"

    def scan(self, code: str, filename: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return vulns

        lines = code.splitlines()

        for node in ast.walk(tree):
            # ----------------------------------------------------------------
            # Detect: "SELECT ... " + variable  (BinOp with Add)
            # ----------------------------------------------------------------
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                concat_str = self._extract_string_from_binop(node)
                if concat_str and SQL_KEYWORDS.search(concat_str):
                    snippet = self._get_snippet(lines, node.lineno)
                    vulns.append(Vulnerability(
                        rule_id="SQL001",
                        severity="critical",
                        title="SQL Injection via String Concatenation",
                        description=(
                            "SQL query is constructed by concatenating user-controlled strings. "
                            "An attacker can manipulate the query to read, modify, or delete data."
                        ),
                        file=filename,
                        line_start=node.lineno,
                        line_end=getattr(node, "end_lineno", node.lineno),
                        code_snippet=snippet,
                        category="SQL Injection",
                        cwe_id="CWE-89",
                        recommendation=(
                            "Use parameterized queries or prepared statements. "
                            "Example: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
                        ),
                    ))

            # ----------------------------------------------------------------
            # Detect: f"SELECT ... {variable}"  (JoinedStr / f-string)
            # ----------------------------------------------------------------
            if isinstance(node, ast.JoinedStr):
                fstr_value = self._extract_fstring_text(node)
                if fstr_value and SQL_KEYWORDS.search(fstr_value):
                    snippet = self._get_snippet(lines, node.lineno)
                    vulns.append(Vulnerability(
                        rule_id="SQL002",
                        severity="critical",
                        title="SQL Injection via f-String Interpolation",
                        description=(
                            "An f-string is used to build a SQL query with embedded variables. "
                            "This allows attackers to inject arbitrary SQL."
                        ),
                        file=filename,
                        line_start=node.lineno,
                        line_end=getattr(node, "end_lineno", node.lineno),
                        code_snippet=snippet,
                        category="SQL Injection",
                        cwe_id="CWE-89",
                        recommendation=(
                            "Replace f-string query construction with parameterized queries. "
                            "Example: cursor.execute('SELECT * FROM users WHERE name = %s', (name,))"
                        ),
                    ))

            # ----------------------------------------------------------------
            # Detect: "SELECT ...".format(variable)  (Call with .format)
            # ----------------------------------------------------------------
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
                and isinstance(node.func.value, ast.Constant)
                and isinstance(node.func.value.value, str)
                and SQL_KEYWORDS.search(node.func.value.value)
            ):
                snippet = self._get_snippet(lines, node.lineno)
                vulns.append(Vulnerability(
                    rule_id="SQL003",
                    severity="critical",
                    title="SQL Injection via .format() String Formatting",
                    description=(
                        "A SQL query string uses .format() to embed variables. "
                        "Attackers can inject malicious SQL through the formatted values."
                    ),
                    file=filename,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    code_snippet=snippet,
                    category="SQL Injection",
                    cwe_id="CWE-89",
                    recommendation=(
                        "Use parameterized queries instead of .format(). "
                        "Example: cursor.execute('SELECT * FROM t WHERE id = %s', (val,))"
                    ),
                ))

            # ----------------------------------------------------------------
            # Detect: "SELECT ..." % variable  (BinOp with Mod = % formatting)
            # ----------------------------------------------------------------
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                left_str = self._const_str(node.left)
                if left_str and SQL_KEYWORDS.search(left_str):
                    snippet = self._get_snippet(lines, node.lineno)
                    vulns.append(Vulnerability(
                        rule_id="SQL004",
                        severity="critical",
                        title="SQL Injection via % String Formatting",
                        description=(
                            "A SQL query uses Python's % operator to embed values directly. "
                            "This is a classic SQL injection vector."
                        ),
                        file=filename,
                        line_start=node.lineno,
                        line_end=getattr(node, "end_lineno", node.lineno),
                        code_snippet=snippet,
                        category="SQL Injection",
                        cwe_id="CWE-89",
                        recommendation=(
                            "Use parameterized queries. "
                            "Example: cursor.execute('SELECT * FROM t WHERE id = %s', (val,))"
                        ),
                    ))

        return vulns

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _const_str(self, node: ast.expr) -> str:
        """Return string value if node is a string constant, else ''."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return ""

    def _extract_string_from_binop(self, node: ast.BinOp) -> str:
        """Try to extract any string literal embedded in a binary + chain."""
        parts = []
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                parts.append(child.value)
        return " ".join(parts)

    def _extract_fstring_text(self, node: ast.JoinedStr) -> str:
        """Extract the static text portions of an f-string."""
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
        return " ".join(parts)

    def _get_snippet(self, lines: List[str], lineno: int, context: int = 2) -> str:
        start = max(0, lineno - 1 - context)
        end = min(len(lines), lineno + context)
        return "\n".join(lines[start:end])
