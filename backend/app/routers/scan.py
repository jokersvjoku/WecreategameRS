"""Scan, patch, rescan, and explain API routes."""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.models.schemas import (
    ExplainRequest,
    PatchRequest,
    PatchResult,
    RescanRequest,
    RescanResult,
    ScanRequest,
    ScanResult,
)
from app.scanners.engine import ScanEngine
from app.services.ai_service import GemmaAIService

logger = logging.getLogger("patchpilot.router.scan")
router = APIRouter(prefix="/api", tags=["scan"])

# Shared instances
_engine = ScanEngine()
_ai = GemmaAIService()


# ------------------------------------------------------------------
# POST /api/scan  — body OR file upload
# ------------------------------------------------------------------
@router.post("/scan", response_model=ScanResult)
async def scan_code(
    request: Optional[ScanRequest] = None,
    file: Optional[UploadFile] = File(default=None),
    language: Optional[str] = Form(default=None),
) -> ScanResult:
    """Scan source code for security vulnerabilities.

    Accepts either a JSON body (ScanRequest) or a multipart file upload.
    """
    if file is not None:
        raw = await file.read()
        code = raw.decode("utf-8", errors="replace")
        fname = file.filename or "uploaded_file.py"
        lang = language or "python"
        return _engine.run_scan(code, language=lang, filename=fname)

    if request is not None:
        return _engine.run_scan(
            request.code,
            language=request.language,
            filename=request.filename,
        )

    raise HTTPException(status_code=400, detail="Provide a JSON body or a file upload.")


# ------------------------------------------------------------------
# GET /api/scan/{scan_id}
# ------------------------------------------------------------------
@router.get("/scan/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str) -> ScanResult:
    """Retrieve a previous scan result by its ID."""
    result = ScanEngine.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")
    return result


# ------------------------------------------------------------------
# POST /api/patch
# ------------------------------------------------------------------
@router.post("/patch", response_model=PatchResult)
async def generate_patch(request: PatchRequest) -> PatchResult:
    """Generate security patches for a previous scan."""
    scan = ScanEngine.get_scan(request.scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {request.scan_id} not found.")

    original_code = ScanEngine.get_code(request.scan_id)
    if original_code is None:
        raise HTTPException(status_code=404, detail="Original source code not found.")

    # Determine which vulnerabilities to patch
    if request.vulnerability_index is not None:
        if request.vulnerability_index < 0 or request.vulnerability_index >= len(
            scan.vulnerabilities
        ):
            raise HTTPException(
                status_code=400,
                detail=f"vulnerability_index {request.vulnerability_index} out of range.",
            )
        vulns_to_patch = [scan.vulnerabilities[request.vulnerability_index]]
    else:
        vulns_to_patch = scan.vulnerabilities

    patched_code, explanation = await _ai.generate_patch(original_code, vulns_to_patch)

    patches_applied = [
        {
            "rule_id": v.rule_id,
            "description": v.title,
            "line_number": v.line_number,
        }
        for v in vulns_to_patch
    ]

    return PatchResult(
        scan_id=request.scan_id,
        original_code=original_code,
        patched_code=patched_code,
        patches_applied=patches_applied,
        ai_explanation=explanation,
    )


# ------------------------------------------------------------------
# POST /api/rescan
# ------------------------------------------------------------------
@router.post("/rescan", response_model=RescanResult)
async def rescan_code(request: RescanRequest) -> RescanResult:
    """Re-scan patched code and compare with the original scan."""
    original_scan = ScanEngine.get_scan(request.scan_id)
    if original_scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {request.scan_id} not found.")

    new_scan = _engine.run_scan(
        request.patched_code,
        language=original_scan.language,
        filename=original_scan.filename,
    )

    original_count = len(original_scan.vulnerabilities)
    new_count = len(new_scan.vulnerabilities)

    return RescanResult(
        original_scan=original_scan,
        rescan=new_scan,
        vulnerabilities_fixed=max(0, original_count - new_count),
        vulnerabilities_remaining=new_count,
    )


# ------------------------------------------------------------------
# POST /api/explain
# ------------------------------------------------------------------
@router.post("/explain")
async def explain_vulnerability(request: ExplainRequest) -> dict:
    """Get an AI-powered explanation of a specific vulnerability."""
    scan = ScanEngine.get_scan(request.scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {request.scan_id} not found.")

    if request.vulnerability_index < 0 or request.vulnerability_index >= len(
        scan.vulnerabilities
    ):
        raise HTTPException(
            status_code=400,
            detail=f"vulnerability_index {request.vulnerability_index} out of range.",
        )

    vuln = scan.vulnerabilities[request.vulnerability_index]
    code_snippet = vuln.snippet or ""

    explanation = await _ai.explain_vulnerability(vuln, code_snippet)

    return {
        "scan_id": request.scan_id,
        "vulnerability_index": request.vulnerability_index,
        "vulnerability": vuln.model_dump(),
        "explanation": explanation,
        "ai_powered": _ai.is_available(),
    }
