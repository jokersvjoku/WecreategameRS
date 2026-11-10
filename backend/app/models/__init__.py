from __future__ import annotations
from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


# ---------------------------------------------------------------------------
# Vulnerability
# ---------------------------------------------------------------------------

class Vulnerability(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str
    severity: str  # critical | high | medium | low | info
    title: str
    description: str
    file: str = "uploaded_code.py"
    line_start: int
    line_end: int
    code_snippet: str
    category: str
    cwe_id: Optional[str] = None
    recommendation: str


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    code: str
    language: str = "python"
    filename: Optional[str] = None


class ScanSummary(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vulnerabilities: List[Vulnerability] = []
    summary: ScanSummary
    scanned_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    language: str = "python"
    filename: str = "uploaded_code.py"


# ---------------------------------------------------------------------------
# Patch
# ---------------------------------------------------------------------------

class PatchRequest(BaseModel):
    code: str
    vulnerabilities: List[Vulnerability]
    scan_id: str


class Patch(BaseModel):
    vulnerability_id: str
    original_code: str
    patched_code: str
    explanation: str
    confidence: float  # 0.0 - 1.0


class PatchResult(BaseModel):
    scan_id: str
    patches: List[Patch]
    patched_code_full: str
    ai_available: bool


# ---------------------------------------------------------------------------
# Re-scan
# ---------------------------------------------------------------------------

class RescanRequest(BaseModel):
    code: str
    language: str = "python"


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

class ReportRequest(BaseModel):
    scan_id: str
    original_code: str
    patched_code: Optional[str] = None
    vulnerabilities: List[Vulnerability]
    patches: Optional[List[Patch]] = None


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str
    version: str
    ai_available: bool
    scanners_available: List[str]
