"""FastAPI Application Entry Point for Automated Threat Intelligence Aggregator & Feed Scoring Engine."""

import logging
import os
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from api.routers.exports import router as exports_router
from api.routers.indicators import router as indicators_router
from cti_core.database import AsyncSessionLocal, ensure_db_initialized, init_db
from cti_core.pipeline import seed_mock_data_if_empty

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cti_engine")


class VercelPathNormalizerMiddleware:
    """Pure ASGI middleware to normalize request paths when running on Vercel serverless."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") == "http":
            raw_query: bytes = scope.get("query_string", b"")
            query_str: str = raw_query.decode("utf-8", errors="ignore")

            # Check 1: query parameter __vercel_path__ injected by vercel.json rewrite
            if "__vercel_path__=" in query_str:
                params = parse_qs(query_str, keep_blank_values=True)
                if "__vercel_path__" in params and params["__vercel_path__"]:
                    vercel_subpath = params.pop("__vercel_path__")[0]
                    if not vercel_subpath.startswith("/"):
                        vercel_subpath = "/" + vercel_subpath
                    # Normalize path
                    scope["path"] = vercel_subpath
                    scope["raw_path"] = vercel_subpath.encode("utf-8")
                    # Re-encode remaining query parameters
                    new_query = urlencode(params, doseq=True)
                    scope["query_string"] = new_query.encode("utf-8")

            # Check 2: if path is /api/index.py or /index.py without query param
            elif scope.get("path") in ("/api/index.py", "/index.py"):
                headers: Dict[bytes, bytes] = dict(scope.get("headers", []))
                fwd_uri = (
                    headers.get(b"x-forwarded-uri")
                    or headers.get(b"x-original-url")
                    or headers.get(b"x-invoke-path")
                )
                if fwd_uri:
                    orig_path = fwd_uri.decode("utf-8", errors="ignore").split("?")[0]
                    scope["path"] = orig_path
                    scope["raw_path"] = orig_path.encode("utf-8")
                else:
                    scope["path"] = "/api"
                    scope["raw_path"] = b"/api"

        await self.app(scope, receive, send)


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

# Install Vercel path normalizer ASGI middleware
app.add_middleware(VercelPathNormalizerMiddleware)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount feature routers with primary /api/v1 prefix
app.include_router(indicators_router)
app.include_router(exports_router)


# Web file resolution across local dev and Vercel serverless directories
WEB_CANDIDATE_DIRS: List[str] = [
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "web"),
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web"),
    os.path.join(os.getcwd(), "web"),
    os.path.join(os.getcwd(), "api", "web"),
]


def resolve_web_file(filename: str) -> Optional[str]:
    """Locate a frontend asset across local repository and Vercel serverless directories."""
    for base_dir in WEB_CANDIDATE_DIRS:
        candidate = os.path.join(base_dir, filename)
        if os.path.isfile(candidate):
            return candidate
    return None


@app.get("/", response_class=HTMLResponse, tags=["Web Portal"])
async def root_portal() -> Response:
    """Serve the Sentinel CTI interactive frontend portal."""
    filepath = resolve_web_file("index.html")
    if filepath and os.path.isfile(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), status_code=200)
    return JSONResponse(
        content={
            "name": "Automated Threat Intelligence Aggregator & Feed Scoring Engine",
            "version": "1.0.0",
            "status": "online",
            "documentation": "/docs",
        }
    )


@app.get("/styles.css", tags=["Web Portal"])
async def portal_styles() -> Response:
    """Serve portal stylesheet."""
    filepath = resolve_web_file("styles.css")
    if filepath and os.path.isfile(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return Response(content=f.read(), media_type="text/css")
    return Response(content="/* stylesheet not found */", status_code=404, media_type="text/css")


@app.get("/app.js", tags=["Web Portal"])
async def portal_script() -> Response:
    """Serve portal JavaScript application logic."""
    filepath = resolve_web_file("app.js")
    if filepath and os.path.isfile(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return Response(content=f.read(), media_type="application/javascript")
    return Response(content="// script not found", status_code=404, media_type="application/javascript")


@app.get("/api", tags=["Health & Status"])
@app.get("/api/status", tags=["Health & Status"])
@app.get("/status", tags=["Health & Status"])
@app.get("/api/index.py", tags=["Health & Status"])
@app.get("/index.py", tags=["Health & Status"])
async def api_status(request: Request) -> JSONResponse:
    """API status endpoint with metadata and export navigation."""
    await ensure_db_initialized()
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
@app.get("/api/health", tags=["Health & Status"])
@app.get("/api/v1/health", tags=["Health & Status"])
@app.get("/v1/health", tags=["Health & Status"])
async def health_check() -> JSONResponse:
    """Service health probe."""
    await ensure_db_initialized()
    return JSONResponse(content={"status": "healthy", "service": "cti-scoring-engine"})


# Mount static files directory if available
for directory in WEB_CANDIDATE_DIRS:
    if os.path.isdir(directory):
        app.mount("/static", StaticFiles(directory=directory), name="static")
        break
