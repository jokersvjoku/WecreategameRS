import re
import logging
from typing import List, Tuple
from app.models_core import Vulnerability, Patch, PatchResult
from app.services.gemma_client import GemmaClient

logger = logging.getLogger("patchpilot")


class PatchGenerator:
    """Generates security patches using Gemma 4 with rule-based fallback."""

    def __init__(self):
        self._client = GemmaClient()

    async def generate_patches(
        self,
        code: str,
        vulnerabilities: List[Vulnerability],
        scan_id: str,
    ) -> PatchResult:
        patches: List[Patch] = []
        patched_code = code

        for vuln in vulnerabilities:
            if self._client.is_available:
                patch = await self._ai_patch(code, vuln)
            else:
                patch = self._rule_based_patch(code, vuln)

            if patch:
                patches.append(patch)
                # Apply patch to accumulated patched code
                if patch.original_code and patch.patched_code:
                    patched_code = patched_code.replace(
                        patch.original_code, patch.patched_code, 1
                    )

        return PatchResult(
            scan_id=scan_id,
            patches=patches,
            patched_code_full=patched_code,
            ai_available=self._client.is_available,
        )

    # ------------------------------------------------------------------
    # AI-powered patching
    # ------------------------------------------------------------------

    async def _ai_patch(self, code: str, vuln: Vulnerability) -> Patch:
        prompt = f"""You are analyzing a Python security vulnerability.

VULNERABILITY:
- Title: {vuln.title}
- Severity: {vuln.severity}
- Category: {vuln.category}
- CWE: {vuln.cwe_id or 'N/A'}
- Lines {vuln.line_start}-{vuln.line_end}
- Description: {vuln.description}

CODE SNIPPET WITH VULNERABILITY:
```python
{vuln.code_snippet}
```

FULL FILE CODE:
```python
{code[:3000]}
```

Your task:
1. Explain the vulnerability in 2-3 sentences.
2. Provide the EXACT original vulnerable code snippet (copy from above).
3. Provide the FIXED version of that exact snippet.
4. Give a confidence score 0.0-1.0 for your fix.

Respond in this EXACT format:
EXPLANATION: <your explanation>
ORIGINAL_CODE:
```
<exact vulnerable code>
```
PATCHED_CODE:
```
<fixed code>
```
CONFIDENCE: <0.0-1.0>"""

        response = await self._client.generate(prompt, max_tokens=1024)
        if not response:
            return self._rule_based_patch(code, vuln)

        return self._parse_ai_response(response, vuln)

    def _parse_ai_response(self, response: str, vuln: Vulnerability) -> Patch:
        """Parse structured AI response into a Patch object."""
        explanation = ""
        original_code = vuln.code_snippet
        patched_code = vuln.code_snippet
        confidence = 0.7

        try:
            # Extract EXPLANATION
            exp_match = re.search(r"EXPLANATION:\s*(.+?)(?=ORIGINAL_CODE:|$)", response, re.DOTALL)
            if exp_match:
                explanation = exp_match.group(1).strip()

            # Extract ORIGINAL_CODE
            orig_match = re.search(r"ORIGINAL_CODE:\s*```(?:python)?\n?(.*?)```", response, re.DOTALL)
            if orig_match:
                original_code = orig_match.group(1).strip()

            # Extract PATCHED_CODE
            patch_match = re.search(r"PATCHED_CODE:\s*```(?:python)?\n?(.*?)```", response, re.DOTALL)
            if patch_match:
                patched_code = patch_match.group(1).strip()

            # Extract CONFIDENCE
            conf_match = re.search(r"CONFIDENCE:\s*([\d.]+)", response)
            if conf_match:
                confidence = float(conf_match.group(1))
                confidence = max(0.0, min(1.0, confidence))

        except Exception as exc:
            logger.warning(f"Failed to parse AI response: {exc}")
            explanation = response[:500]

        if not explanation:
            explanation = vuln.description

        return Patch(
            vulnerability_id=vuln.id,
            original_code=original_code,
            patched_code=patched_code,
            explanation=explanation,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Rule-based fallback patches
    # ------------------------------------------------------------------

    def _rule_based_patch(self, code: str, vuln: Vulnerability) -> Patch:
        rule_id = vuln.rule_id
        snippet = vuln.code_snippet

        if rule_id in ("SQL001", "SQL002", "SQL003", "SQL004"):
            return Patch(
                vulnerability_id=vuln.id,
                original_code=snippet,
                patched_code=self._fix_sql(snippet),
                explanation=(
                    f"{vuln.description}\n\n"
                    "Rule-based fix: Replace string interpolation with a parameterized query. "
                    "Pass user values as a tuple to cursor.execute(), never inline them into the SQL string."
                ),
                confidence=0.6,
            )

        elif rule_id in ("CRED001", "CRED002", "CRED003", "CRED004"):
            return Patch(
                vulnerability_id=vuln.id,
                original_code=snippet,
                patched_code=self._fix_cred(snippet, vuln),
                explanation=(
                    f"{vuln.description}\n\n"
                    "Rule-based fix: Replace the hardcoded value with an environment variable lookup. "
                    "Store the real value in a .env file that is excluded from version control."
                ),
                confidence=0.75,
            )

        elif rule_id in ("EVAL001",):
            return Patch(
                vulnerability_id=vuln.id,
                original_code=snippet,
                patched_code=snippet.replace("eval(", "ast.literal_eval("),
                explanation=(
                    "Replace eval() with ast.literal_eval() which only evaluates Python literals "
                    "(strings, numbers, lists, dicts, etc.) and raises ValueError for anything else. "
                    "Add 'import ast' at the top of your file."
                ),
                confidence=0.8,
            )

        elif rule_id in ("EVAL002",):
            return Patch(
                vulnerability_id=vuln.id,
                original_code=snippet,
                patched_code="# REMOVED: exec() call — redesign to avoid dynamic code execution\n# " + snippet.replace("\n", "\n# "),
                explanation=(
                    "exec() has been commented out. Redesign the logic to use explicit function calls, "
                    "a dispatch table (dict mapping names to functions), or a plugin architecture "
                    "that does not require executing arbitrary strings as code."
                ),
                confidence=0.5,
            )

        elif rule_id in ("EVAL004",):
            return Patch(
                vulnerability_id=vuln.id,
                original_code=snippet,
                patched_code=snippet.replace("os.system(", "subprocess.run([").replace(")", "], shell=False, check=True)"),
                explanation=(
                    "Replace os.system() with subprocess.run() passing arguments as a list. "
                    "This prevents shell injection because arguments are not interpreted by a shell."
                ),
                confidence=0.6,
            )

        elif rule_id in ("EVAL005",):
            return Patch(
                vulnerability_id=vuln.id,
                original_code=snippet,
                patched_code=snippet.replace("shell=True", "shell=False"),
                explanation=(
                    "Set shell=False and pass the command as a list of arguments. "
                    "When shell=False, the OS does not invoke a shell interpreter, "
                    "preventing injection via shell metacharacters."
                ),
                confidence=0.85,
            )

        elif rule_id in ("PY002",):
            return Patch(
                vulnerability_id=vuln.id,
                original_code=snippet,
                patched_code=snippet.replace("debug=True", "debug=os.environ.get('DEBUG', 'false').lower() == 'true'"),
                explanation=(
                    "Replace the hardcoded debug=True with an environment variable check. "
                    "This ensures debug mode is never accidentally enabled in production."
                ),
                confidence=0.9,
            )

        elif rule_id in ("PY003",):
            return Patch(
                vulnerability_id=vuln.id,
                original_code=snippet,
                patched_code=snippet.replace("import random", "import secrets"),
                explanation=(
                    "Replace the random module with the secrets module for security-sensitive operations. "
                    "secrets.token_urlsafe(32) generates cryptographically secure random tokens."
                ),
                confidence=0.8,
            )

        else:
            return Patch(
                vulnerability_id=vuln.id,
                original_code=snippet,
                patched_code=snippet,
                explanation=(
                    f"Manual review required for: {vuln.title}\n\n"
                    f"Recommendation: {vuln.recommendation}"
                ),
                confidence=0.3,
            )

    def _fix_sql(self, snippet: str) -> str:
        """Best-effort SQL injection fix for simple cases."""
        # Replace f-string SQL with a comment showing parameterized form
        lines = snippet.splitlines()
        fixed = []
        for line in lines:
            if any(kw in line.upper() for kw in ["SELECT", "INSERT", "UPDATE", "DELETE"]):
                fixed.append("# PATCHPILOT: Use parameterized query below:")
                fixed.append("# cursor.execute('YOUR SQL HERE', (param1, param2))")
                fixed.append("# Original (UNSAFE): " + line.strip())
            else:
                fixed.append(line)
        return "\n".join(fixed)

    def _fix_cred(self, snippet: str, vuln: Vulnerability) -> str:
        """Replace hardcoded credential assignment with os.environ.get."""
        import re
        # Try to extract variable name
        m = re.search(r"([\w]+)\s*=\s*[\"'][^\"']*[\"']", snippet)
        if m:
            var = m.group(1)
            env_key = var.upper()
            fixed = snippet.replace(
                m.group(0),
                f"{var} = os.environ.get('{env_key}', '')  # Load from environment"
            )
            return "import os\n" + fixed if "import os" not in snippet else fixed
        return snippet
