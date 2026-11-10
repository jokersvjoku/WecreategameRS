import os
import re
from fastapi import HTTPException


def validate_code_size(code: str, max_kb: int) -> None:
    """Raise HTTP 413 if code exceeds the maximum allowed size."""
    size_kb = len(code.encode("utf-8")) / 1024
    if size_kb > max_kb:
        raise HTTPException(
            status_code=413,
            detail=f"Code size ({size_kb:.1f} KB) exceeds limit of {max_kb} KB.",
        )


def detect_language(code: str, filename: str | None) -> str:
    """Detect programming language from filename extension or content heuristics."""
    if filename:
        ext = os.path.splitext(filename.lower())[1]
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".rb": "ruby",
            ".php": "php",
            ".java": "java",
            ".go": "go",
        }
        if ext in ext_map:
            return ext_map[ext]

    # Content heuristics for Python
    python_indicators = ["import ", "def ", "class ", "from ", "print(", "if __name__"]
    matches = sum(1 for ind in python_indicators if ind in code)
    if matches >= 2:
        return "python"

    return "python"  # Default to python for now


def sanitize_filename(filename: str | None) -> str:
    """Strip path traversal and unsafe characters from a filename."""
    if not filename:
        return "uploaded_code.py"
    # Remove directory components
    basename = os.path.basename(filename)
    # Allow only alphanumeric, dot, dash, underscore
    safe = re.sub(r"[^A-Za-z0-9._\-]", "_", basename)
    # Limit length
    return safe[:128] or "uploaded_code.py"
