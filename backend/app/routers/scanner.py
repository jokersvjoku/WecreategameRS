from fastapi import APIRouter, HTTPException
from app.models import ScanRequest, ScanResult, RescanRequest
from app.scanners.engine import ScanEngine
from app.utils.sanitizer import validate_code_size, detect_language, sanitize_filename
from app.config import get_settings

router = APIRouter()
engine = ScanEngine()


@router.post("/scan", response_model=ScanResult)
async def scan_code(request: ScanRequest) -> ScanResult:
    settings = get_settings()
    validate_code_size(request.code, settings.max_code_size_kb)

    language = detect_language(request.code, request.filename)
    filename = sanitize_filename(request.filename) if request.filename else "uploaded_code.py"

    if language != "python":
        raise HTTPException(status_code=400, detail="Only Python code is currently supported.")

    result = engine.run_scan(request.code, language, filename)
    return result


@router.post("/rescan", response_model=ScanResult)
async def rescan_code(request: RescanRequest) -> ScanResult:
    settings = get_settings()
    validate_code_size(request.code, settings.max_code_size_kb)

    language = detect_language(request.code, None)
    result = engine.run_scan(request.code, language, "patched_code.py")
    return result
