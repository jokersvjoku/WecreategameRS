from fastapi import APIRouter
from app.models import PatchRequest, PatchResult
from app.services.patch_generator import PatchGenerator
from app.utils.sanitizer import validate_code_size
from app.config import get_settings

router = APIRouter()


@router.post("/patch", response_model=PatchResult)
async def generate_patch(request: PatchRequest) -> PatchResult:
    settings = get_settings()
    validate_code_size(request.code, settings.max_code_size_kb)

    generator = PatchGenerator()
    result = await generator.generate_patches(
        request.code,
        request.vulnerabilities,
        request.scan_id,
    )
    return result
