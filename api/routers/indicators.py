"""FastAPI router for querying, creating, and inspecting Indicators of Compromise (IoCs)."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cti_core.database import get_db_session
from cti_core.models.indicator import (
    ConfidenceTier,
    IndicatorCreate,
    IndicatorModel,
    IndicatorRead,
    ScoreBreakdown,
    SourceMetadata,
)
from cti_core.pipeline import CTIPipeline, global_pipeline

router = APIRouter(prefix="/api/v1", tags=["Indicators"])


def model_to_read_schema(ind: IndicatorModel) -> IndicatorRead:
    """Convert an IndicatorModel ORM object to an IndicatorRead Pydantic model."""
    score_breakdown_dict: Dict[str, Any] = ind.score_breakdown or {}  # type: ignore
    score_obj = ScoreBreakdown(**score_breakdown_dict) if score_breakdown_dict else None

    # Derive tier
    score_val = float(ind.confidence_score)  # type: ignore
    tier = ConfidenceTier.LOW
    if score_val >= 85.0:
        tier = ConfidenceTier.CRITICAL
    elif score_val >= 70.0:
        tier = ConfidenceTier.HIGH
    elif score_val >= 40.0:
        tier = ConfidenceTier.MEDIUM

    sources = [
        SourceMetadata(
            source_name=str(s.source_name),
            confidence=float(s.confidence) if s.confidence is not None else None,  # type: ignore
            reported_at=s.reported_at,
            reference_url=str(s.reference_url) if s.reference_url is not None else None,
            raw_tags=list(s.raw_tags or []),
        )
        for s in (ind.sources or [])
    ]

    return IndicatorRead(
        id=str(ind.id),
        value=str(ind.value),
        normalized_value=str(ind.normalized_value),
        type=ind.type,  # type: ignore
        confidence_score=score_val,
        confidence_tier=tier,
        severity=ind.severity,  # type: ignore
        tags=list(ind.tags or []),
        is_whitelisted=bool(ind.is_whitelisted),
        whitelist_reason=str(ind.whitelist_reason) if ind.whitelist_reason is not None else None,
        first_seen=ind.first_seen,  # type: ignore
        last_seen=ind.last_seen,  # type: ignore
        sources=sources,
        enrichment=dict(ind.enrichment_data or {}),
        score_breakdown=score_obj,
        created_at=ind.created_at,  # type: ignore
        updated_at=ind.updated_at,  # type: ignore
    )


@router.get(
    "/indicators",
    response_model=List[IndicatorRead],
    summary="Query Indicators of Compromise",
    description="Search indicators by type, minimum/maximum score, tag, or keyword with pagination.",
)
async def list_indicators(
    type: Optional[str] = Query(None, description="Indicator type: ip, ipv4, ipv6, domain, url, hash, md5, sha1, sha256, cve"),
    min_score: Optional[float] = Query(None, ge=0.0, le=100.0, description="Minimum confidence score threshold"),
    max_score: Optional[float] = Query(None, ge=0.0, le=100.0, description="Maximum confidence score threshold"),
    tag: Optional[str] = Query(None, description="Tag to filter by (e.g. cobalt-strike, c2, scanner)"),
    search: Optional[str] = Query(None, description="Partial search query on indicator value"),
    is_whitelisted: Optional[bool] = Query(None, description="Filter by whitelisted status"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    session: AsyncSession = Depends(get_db_session),
) -> List[IndicatorRead]:
    """Retrieve filtered IoCs from the database."""
    stmt = select(IndicatorModel)

    if type:
        t = type.lower()
        if t == "ip":
            stmt = stmt.where(IndicatorModel.type.in_(["ipv4", "ipv6"]))
        elif t == "hash":
            stmt = stmt.where(IndicatorModel.type.in_(["md5", "sha1", "sha256"]))
        else:
            stmt = stmt.where(IndicatorModel.type == t)

    if min_score is not None:
        stmt = stmt.where(IndicatorModel.confidence_score >= min_score)

    if max_score is not None:
        stmt = stmt.where(IndicatorModel.confidence_score <= max_score)

    if is_whitelisted is not None:
        stmt = stmt.where(IndicatorModel.is_whitelisted == is_whitelisted)

    if search:
        stmt = stmt.where(IndicatorModel.value.ilike(f"%{search}%"))

    stmt = stmt.order_by(IndicatorModel.confidence_score.desc()).limit(limit).offset(offset)
    result = await session.execute(stmt)
    records = result.scalars().all()

    # Tag post-filter for JSON array field
    if tag:
        tag_lower = tag.lower()
        records = [r for r in records if any(tag_lower == t.lower() for t in list(r.tags or []))]

    return [model_to_read_schema(r) for r in records]


@router.post(
    "/indicators",
    response_model=IndicatorRead,
    status_code=status.HTTP_201_CREATED,
    summary="Submit and Score Indicator",
    description="Manually submit an IoC for automated normalization, enrichment, scoring, and storage.",
)
async def create_indicator(
    payload: IndicatorCreate,
    session: AsyncSession = Depends(get_db_session),
) -> IndicatorRead:
    """Ingest, normalize, enrich, score, and persist a single indicator."""
    raw_dict = {
        "value": payload.value,
        "type": payload.type.value if payload.type else None,
        "source": payload.source_name,
        "severity": payload.severity.value,
        "tags": payload.tags,
        "reference_url": payload.reference_url,
        "reported_at": payload.reported_at.isoformat() if payload.reported_at else None,
    }

    pipeline = CTIPipeline()
    processed = await pipeline.process_and_score([raw_dict])
    if not processed:
        raise HTTPException(status_code=400, detail="Invalid indicator format or unable to normalize.")

    await pipeline.persist_to_database(session, processed)

    # Fetch newly saved indicator
    stmt = select(IndicatorModel).where(
        IndicatorModel.type == processed[0]["type"],
        IndicatorModel.normalized_value == processed[0]["normalized_value"],
    )
    res = await session.execute(stmt)
    record = res.scalars().first()
    if not record:
        raise HTTPException(status_code=500, detail="Failed to retrieve persisted indicator.")

    return model_to_read_schema(record)


@router.get(
    "/indicators/{value:path}",
    response_model=IndicatorRead,
    summary="Get Indicator Details",
    description="Retrieve deep metadata, enrichment results, and mathematical score breakdown for an IoC.",
)
async def get_indicator_by_value(
    value: str,
    session: AsyncSession = Depends(get_db_session),
) -> IndicatorRead:
    """Look up an indicator by raw or normalized value."""
    stmt = select(IndicatorModel).where(
        (IndicatorModel.value == value) | (IndicatorModel.normalized_value == value)
    )
    result = await session.execute(stmt)
    record = result.scalars().first()
    if not record:
        raise HTTPException(status_code=404, detail=f"Indicator '{value}' not found.")

    return model_to_read_schema(record)


@router.post(
    "/pipeline/run",
    summary="Trigger Ingestion Pipeline",
    description="Execute an automated ingestion, normalization, enrichment, and scoring cycle.",
)
async def run_pipeline_cycle(
    live: bool = Query(False, description="Whether to query live external feeds (requires internet/API keys)"),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Execute pipeline ingestion cycle."""
    result = await global_pipeline.run_pipeline(session, use_live=live)
    return result
