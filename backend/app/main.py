import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.routers import scanner, patcher, report

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("patchpilot")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logger.info("PATCHPILOT backend starting")
    logger.info(f"AI available: {settings.ai_available}")
    logger.info(f"CORS origins: {settings.cors_origins_list}")
    yield
    logger.info("PATCHPILOT backend shutting down")


app = FastAPI(
    title="PATCHPILOT API",
    description="Find the flaw. Fix the code. Prove the patch.",
    version="1.0.0",
    lifespan=lifespan,
)

settings = get_settings()

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scanner.router, prefix="/api")
app.include_router(patcher.router, prefix="/api")
app.include_router(report.router, prefix="/api")


from app.models import HealthResponse  # noqa: E402

@app.get("/api/health", response_model=HealthResponse)
async def health():
    s = get_settings()
    return HealthResponse(
        status="ok",
        version="1.0.0",
        ai_available=s.ai_available,
        scanners_available=["sql_injection", "hardcoded_creds", "unsafe_eval", "python_static"],
    )
