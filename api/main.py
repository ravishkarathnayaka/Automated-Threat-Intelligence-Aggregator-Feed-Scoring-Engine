"""FastAPI Application Entry Point for Automated Threat Intelligence Aggregator & Feed Scoring Engine."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.routers.exports import router as exports_router
from api.routers.indicators import router as indicators_router
from cti_core.database import AsyncSessionLocal, init_db
from cti_core.pipeline import seed_mock_data_if_empty

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cti_engine")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle management."""
    logger.info("Initializing CTI Database tables...")
    await init_db()

    # Seed initial test data so engine is immediately queryable on fresh run
    async with AsyncSessionLocal() as session:
        seeded = await seed_mock_data_if_empty(session)
        if seeded:
            logger.info("Successfully populated initial high-confidence threat feed.")

    yield
    logger.info("Shutting down CTI Engine...")


app = FastAPI(
    title="Automated Threat Intelligence Aggregator & Feed Scoring Engine",
    description=(
        "Production-grade Cyber Threat Intelligence (CTI) engine. Ingests indicators across "
        "open-source and STIX/TAXII feeds, normalizes IoCs, enriches against intelligence APIs, "
        "computes transparent multi-factor confidence scores, and exports enforcement feeds "
        "(Firewall IP blocklists, STIX 2.1 bundles, DNS RPZ, and Suricata/Snort rules)."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount feature routers
app.include_router(indicators_router)
app.include_router(exports_router)


@app.get("/", tags=["Health & Status"])
async def root() -> JSONResponse:
    """Root status endpoint with API information and export navigation."""
    return JSONResponse(
        content={
            "name": "Automated Threat Intelligence Aggregator & Feed Scoring Engine",
            "version": "1.0.0",
            "status": "online",
            "documentation": "/docs",
            "endpoints": {
                "indicators": "/api/v1/indicators",
                "export_firewall": "/api/v1/export/firewall.txt",
                "export_stix": "/api/v1/export/stix.json",
                "export_dns_rpz": "/api/v1/export/dns-rpz.zone",
                "export_suricata": "/api/v1/export/suricata.rules",
                "export_snort": "/api/v1/export/snort.rules",
                "trigger_pipeline": "/api/v1/pipeline/run",
            },
        }
    )


@app.get("/health", tags=["Health & Status"])
@app.get("/api/v1/health", tags=["Health & Status"])
async def health_check() -> JSONResponse:
    """Service health probe."""
    return JSONResponse(content={"status": "healthy", "service": "cti-scoring-engine"})
