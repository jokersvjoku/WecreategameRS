"""Pydantic models for PATCHPILOT API request/response schemas."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanRequest(BaseModel):
    """Request body for initiating a code scan."""
    code: str = Field(..., description="Source code to scan")
    language: str = Field(default="python", description="Programming language of the code")
    filename: Optional[str] = Field(default=None, description="Original filename of the code")


class VulnerabilityDetail(BaseModel):
    """Detailed information about a single detected vulnerability."""
    rule_id: str = Field(..., description="Unique rule identifier, e.g. SQLI-001")
    severity: Severity = Field(..., description="Severity level")
    title: str = Field(..., description="Short title of the vulnerability")
    description: str = Field(..., description="Detailed description of the issue")
    line_number: Optional[int] = Field(default=None, description="Line where the issue was found")
    column: Optional[int] = Field(default=None, description="Column offset")
    snippet: Optional[str] = Field(default=None, description="Relevant code snippet")
    cwe_id: Optional[str] = Field(default=None, description="CWE identifier, e.g. CWE-89")


class ScanResult(BaseModel):
    """Complete result of a code scan."""
    scan_id: str = Field(..., description="UUID identifying this scan")
    filename: Optional[str] = Field(default=None, description="Scanned filename")
    language: str = Field(..., description="Language that was scanned")
    vulnerabilities: List[VulnerabilityDetail] = Field(default_factory=list)
    scan_time: float = Field(..., description="Duration in seconds")
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    summary: Dict[str, int] = Field(
        default_factory=dict,
        description="Counts of vulnerabilities by severity",
    )


class PatchRequest(BaseModel):
    """Request to generate patches for a previous scan."""
    scan_id: str = Field(..., description="UUID of the scan to patch")
    vulnerability_index: Optional[int] = Field(
        default=None,
        description="Index of specific vulnerability to patch; omit to patch all",
    )


class PatchResult(BaseModel):
    """Result of a patch generation."""
    scan_id: str
    original_code: str
    patched_code: str
    patches_applied: List[Dict[str, Any]] = Field(default_factory=list)
    ai_explanation: Optional[str] = Field(default=None)


class RescanRequest(BaseModel):
    """Request to re-scan patched code and compare with the original scan."""
    scan_id: str = Field(..., description="Original scan ID to compare against")
    patched_code: str = Field(..., description="The patched code to re-scan")


class RescanResult(BaseModel):
    """Comparison between original scan and re-scan of patched code."""
    original_scan: ScanResult
    rescan: ScanResult
    vulnerabilities_fixed: int
    vulnerabilities_remaining: int


class ReportRequest(BaseModel):
    """Request to generate a report for a completed scan."""
    scan_id: str
    include_patches: bool = Field(default=True)


class ExplainRequest(BaseModel):
    """Request an AI explanation of a specific vulnerability."""
    scan_id: str
    vulnerability_index: int
