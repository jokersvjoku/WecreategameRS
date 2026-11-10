import ast
from typing import List, Optional
from app.models_core import Vulnerability
from app.scanners.base import BaseScanner


class UnsafeEvalScanner(BaseScanner):
    """Detects dangerous code execution patterns via AST analysis."""

    @property
    def name(self) -> str:
        return "unsafe_eval"

    def scan(self, code: str, filename: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return vulns

        lines = code.splitlines()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func_name = self._get_func_name(node)

            # ----------------------------------------------------------------
            # eval()
            # ----------------------------------------------------------------
            if func_name == "eval":
                snippet = self._get_snippet(lines, node.lineno)
                vulns.append(Vulnerability(
                    rule_id="EVAL001",
                    severity="critical",
                    title="Use of eval() with Potentially Unsafe Input",
                    description=(
                        "eval() executes arbitrary Python code from a string. "
                        "If any part of the input is user-controlled, an attacker can "
                        "execute arbitrary code on the server."
                    ),
                    file=filename,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    code_snippet=snippet,
                    category="Code Injection",
                    cwe_id="CWE-95",
                    recommendation=(
                        "Replace eval() with ast.literal_eval() for safe literal parsing, "
                        "or redesign the logic to avoid dynamic code evaluation entirely."
                    ),
                ))

            # ----------------------------------------------------------------
            # exec()
            # ----------------------------------------------------------------
            elif func_name == "exec":
                snippet = self._get_snippet(lines, node.lineno)
                vulns.append(Vulnerability(
                    rule_id="EVAL002",
                    severity="critical",
                    title="Use of exec() — Arbitrary Code Execution Risk",
                    description=(
                        "exec() executes arbitrary Python code. "
                        "User-controlled input passed to exec() enables full remote code execution."
                    ),
                    file=filename,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    code_snippet=snippet,
                    category="Code Injection",
                    cwe_id="CWE-95",
                    recommendation=(
                        "Avoid exec() entirely. Refactor to use explicit function calls "
                        "or a whitelist of allowed operations."
                    ),
                ))

            # ----------------------------------------------------------------
            # compile()
            # ----------------------------------------------------------------
            elif func_name == "compile":
                snippet = self._get_snippet(lines, node.lineno)
                vulns.append(Vulnerability(
                    rule_id="EVAL003",
                    severity="high",
                    title="Use of compile() — Dynamic Code Compilation",
                    description=(
                        "compile() creates executable code objects from strings. "
                        "Combined with exec(), it enables arbitrary code execution."
                    ),
                    file=filename,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    code_snippet=snippet,
                    category="Code Injection",
                    cwe_id="CWE-95",
                    recommendation=(
                        "Avoid dynamic code compilation. Use data structures or "
                        "configuration-driven logic instead."
                    ),
                ))

            # ----------------------------------------------------------------
            # os.system()
            # ----------------------------------------------------------------
            elif func_name in ("os.system", "system"):
                snippet = self._get_snippet(lines, node.lineno)
                vulns.append(Vulnerability(
                    rule_id="EVAL004",
                    severity="critical",
                    title="Use of os.system() — Command Injection Risk",
                    description=(
                        "os.system() executes shell commands. "
                        "User-controlled input allows OS command injection, "
                        "giving attackers full system access."
                    ),
                    file=filename,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    code_snippet=snippet,
                    category="OS Command Injection",
                    cwe_id="CWE-78",
                    recommendation=(
                        "Use subprocess.run() with a list of arguments (not shell=True) "
                        "and validate all inputs: subprocess.run(['cmd', arg], shell=False)"
                    ),
                ))

            # ----------------------------------------------------------------
            # subprocess with shell=True
            # ----------------------------------------------------------------
            elif func_name in (
                "subprocess.call", "subprocess.run", "subprocess.Popen",
                "subprocess.check_output", "subprocess.check_call",
                "call", "run", "Popen", "check_output", "check_call",
            ):
                if self._has_shell_true(node):
                    snippet = self._get_snippet(lines, node.lineno)
                    vulns.append(Vulnerability(
                        rule_id="EVAL005",
                        severity="high",
                        title="subprocess Called with shell=True",
                        description=(
                            "Calling subprocess functions with shell=True enables shell injection. "
                            "Any unsanitized string passed as the command can be exploited."
                        ),
                        file=filename,
                        line_start=node.lineno,
                        line_end=getattr(node, "end_lineno", node.lineno),
                        code_snippet=snippet,
                        category="OS Command Injection",
                        cwe_id="CWE-78",
                        recommendation=(
                            "Pass a list of arguments instead of a shell string, and set shell=False: "
                            "subprocess.run(['program', arg1, arg2], shell=False)"
                        ),
                    ))

            # ----------------------------------------------------------------
            # pickle.loads()
            # ----------------------------------------------------------------
            elif func_name in ("pickle.loads", "pickle.load", "loads", "load"):
                # Only flag if it's in a pickle context
                if self._is_pickle_context(node, code):
                    snippet = self._get_snippet(lines, node.lineno)
                    vulns.append(Vulnerability(
                        rule_id="EVAL006",
                        severity="high",
                        title="Insecure Deserialization with pickle",
                        description=(
                            "pickle.loads() deserializes arbitrary Python objects. "
                            "Deserializing untrusted data can execute arbitrary code "
                            "during the unpickling process."
                        ),
                        file=filename,
                        line_start=node.lineno,
                        line_end=getattr(node, "end_lineno", node.lineno),
                        code_snippet=snippet,
                        category="Insecure Deserialization",
                        cwe_id="CWE-502",
                        recommendation=(
                            "Never deserialize pickle data from untrusted sources. "
                            "Use JSON or another safe format for external data exchange."
                        ),
                    ))

            # ----------------------------------------------------------------
            # __import__()
            # ----------------------------------------------------------------
            elif func_name == "__import__":
                snippet = self._get_snippet(lines, node.lineno)
                vulns.append(Vulnerability(
                    rule_id="EVAL007",
                    severity="medium",
                    title="Dynamic Import via __import__()",
                    description=(
                        "__import__() loads modules dynamically. "
                        "If the module name comes from user input, it allows loading "
                        "arbitrary modules, potentially enabling code execution."
                    ),
                    file=filename,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    code_snippet=snippet,
                    category="Code Injection",
                    cwe_id="CWE-95",
                    recommendation=(
                        "Use explicit imports instead of __import__(). "
                        "If dynamic imports are needed, validate against a whitelist of allowed modules."
                    ),
                ))

        return vulns

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_func_name(self, node: ast.Call) -> str:
        """Return a dot-notation function name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            obj = self._get_func_name_from_expr(node.func.value)
            return f"{obj}.{node.func.attr}" if obj else node.func.attr
        return ""

    def _get_func_name_from_expr(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._get_func_name_from_expr(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    def _has_shell_true(self, node: ast.Call) -> bool:
        """Check if a Call node has shell=True as a keyword argument."""
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False

    def _is_pickle_context(self, node: ast.Call, code: str) -> bool:
        """Check if 'pickle' is imported in the file (to reduce false positives)."""
        return "import pickle" in code or "from pickle" in code

    def _get_snippet(self, lines: List[str], lineno: int, context: int = 2) -> str:
        start = max(0, lineno - 1 - context)
        end = min(len(lines), lineno + context)
        return "\n".join(lines[start:end])
