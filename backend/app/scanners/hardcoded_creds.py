import re
from typing import List, Tuple
from app.models_core import Vulnerability
from app.scanners.base import BaseScanner

# Variable name patterns that suggest credential storage
CRED_VAR_PATTERN = re.compile(
    r"\b(password|passwd|pwd|secret|api_key|apikey|api_secret|access_key|"
    r"access_token|auth_token|private_key|client_secret|db_password|"
    r"database_password|smtp_password|ftp_password|token|credential)\b",
    re.IGNORECASE,
)

# AWS Access Key pattern
AWS_KEY_PATTERN = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")

# Generic high-entropy string pattern (hex, base64-ish, 20+ chars assigned to key variable)
HIGH_ENTROPY_STRING = re.compile(r"""["']([A-Za-z0-9+/=_\-]{20,})["']""")

# GitHub personal access token
GITHUB_TOKEN_PATTERN = re.compile(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b")

# Slack token
SLACK_TOKEN_PATTERN = re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b")

# Generic assignment: varname = "literal string"
ASSIGNMENT_PATTERN = re.compile(
    r"""^[ \t]*([\w]+)\s*=\s*["']([^"']{4,})["']""",
    re.MULTILINE,
)


class HardcodedCredsScanner(BaseScanner):
    """Detects hardcoded credentials and secrets in source code."""

    @property
    def name(self) -> str:
        return "hardcoded_creds"

    def scan(self, code: str, filename: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        lines = code.splitlines()

        # ----------------------------------------------------------------
        # Pass 1: Line-by-line regex for credential variable assignments
        # ----------------------------------------------------------------
        for lineno, line in enumerate(lines, start=1):
            m = ASSIGNMENT_PATTERN.search(line)
            if m:
                var_name = m.group(1)
                value = m.group(2)

                if CRED_VAR_PATTERN.search(var_name) and not self._is_placeholder(value):
                    snippet = self._get_snippet(lines, lineno)
                    vulns.append(Vulnerability(
                        rule_id="CRED001",
                        severity="high",
                        title="Hardcoded Credential Detected",
                        description=(
                            f"Variable '{var_name}' appears to store a hardcoded credential. "
                            "Hardcoded secrets in source code can be exposed via version control, "
                            "logs, error messages, or code reviews."
                        ),
                        file=filename,
                        line_start=lineno,
                        line_end=lineno,
                        code_snippet=snippet,
                        category="Hardcoded Credentials",
                        cwe_id="CWE-798",
                        recommendation=(
                            f"Replace with an environment variable: "
                            f"{var_name} = os.environ.get('{var_name.upper()}', '')\n"
                            "Add the variable to .env and never commit .env to version control."
                        ),
                    ))

            # ----------------------------------------------------------------
            # AWS Access Key
            # ----------------------------------------------------------------
            if AWS_KEY_PATTERN.search(line):
                snippet = self._get_snippet(lines, lineno)
                vulns.append(Vulnerability(
                    rule_id="CRED002",
                    severity="critical",
                    title="Hardcoded AWS Access Key",
                    description=(
                        "An AWS Access Key ID (AKIA...) is hardcoded in the source. "
                        "Exposed AWS keys can lead to full cloud account compromise."
                    ),
                    file=filename,
                    line_start=lineno,
                    line_end=lineno,
                    code_snippet=snippet,
                    category="Hardcoded Credentials",
                    cwe_id="CWE-798",
                    recommendation=(
                        "Remove the key immediately and rotate it in AWS IAM. "
                        "Use AWS environment variables or IAM roles instead."
                    ),
                ))

            # ----------------------------------------------------------------
            # GitHub Token
            # ----------------------------------------------------------------
            if GITHUB_TOKEN_PATTERN.search(line):
                snippet = self._get_snippet(lines, lineno)
                vulns.append(Vulnerability(
                    rule_id="CRED003",
                    severity="critical",
                    title="Hardcoded GitHub Personal Access Token",
                    description=(
                        "A GitHub Personal Access Token is hardcoded. "
                        "Exposed tokens allow unauthorized repository and API access."
                    ),
                    file=filename,
                    line_start=lineno,
                    line_end=lineno,
                    code_snippet=snippet,
                    category="Hardcoded Credentials",
                    cwe_id="CWE-798",
                    recommendation=(
                        "Revoke this token immediately at github.com/settings/tokens. "
                        "Use GitHub Secrets or environment variables."
                    ),
                ))

            # ----------------------------------------------------------------
            # Slack Token
            # ----------------------------------------------------------------
            if SLACK_TOKEN_PATTERN.search(line):
                snippet = self._get_snippet(lines, lineno)
                vulns.append(Vulnerability(
                    rule_id="CRED004",
                    severity="high",
                    title="Hardcoded Slack Token",
                    description=(
                        "A Slack API token is hardcoded in the source code. "
                        "Exposed Slack tokens can allow unauthorized access to workspace data."
                    ),
                    file=filename,
                    line_start=lineno,
                    line_end=lineno,
                    code_snippet=snippet,
                    category="Hardcoded Credentials",
                    cwe_id="CWE-798",
                    recommendation=(
                        "Revoke the Slack token and store it in an environment variable."
                    ),
                ))

        return vulns

    def _is_placeholder(self, value: str) -> bool:
        """Return True if the value looks like a placeholder, not a real secret."""
        placeholders = {
            "", "your_password_here", "your_secret_here", "changeme", "placeholder",
            "xxxxx", "your_api_key", "password", "secret", "token", "replace_me",
            "your_token", "YOUR_PASSWORD", "YOUR_SECRET", "YOUR_API_KEY",
        }
        return value.lower() in placeholders or value.startswith("<") and value.endswith(">")

    def _get_snippet(self, lines: List[str], lineno: int, context: int = 2) -> str:
        start = max(0, lineno - 1 - context)
        end = min(len(lines), lineno + context)
        return "\n".join(lines[start:end])
