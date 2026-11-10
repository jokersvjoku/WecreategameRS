from fastapi import APIRouter
from fastapi.responses import StreamingResponse
import io
from app.models import ReportRequest
from app.services.report_generator import ReportGenerator

router = APIRouter()


@router.post("/report")
async def generate_report(request: ReportRequest):
    generator = ReportGenerator()
    pdf_bytes = generator.generate_pdf(
        scan_id=request.scan_id,
        original_code=request.original_code,
        patched_code=request.patched_code,
        vulnerabilities=request.vulnerabilities,
        patches=request.patches or [],
    )
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="patchpilot-report-{request.scan_id[:8]}.pdf"'
        },
    )
