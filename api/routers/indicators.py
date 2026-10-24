"""FastAPI router for querying, creating, and inspecting Indicators of Compromise (IoCs)."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import case, func, select
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
from cti_core.scoring.beta_distribution_scorer import BetaDistributionScorer
from cti_core.scoring.kalman_confidence_filter import KalmanConfidenceFilter
from cti_core.scoring.markov_threat_state import MarkovThreatStateModel, ThreatState
from cti_core.scoring.weibull_reliability_model import WeibullReliabilityModel

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


@router.post(
    "/indicators/bulk",
    response_model=Dict[str, Any],
    status_code=status.HTTP_201_CREATED,
    summary="Bulk Ingest Indicators",
    description="Batch submit multiple IoCs for automated normalization, deduplication, scoring, and storage.",
)
async def create_indicators_bulk(
    payload: List[IndicatorCreate],
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Ingest, normalize, enrich, score, and persist multiple indicators in a single batch."""
    if not payload:
        raise HTTPException(status_code=400, detail="Payload list cannot be empty.")

    raw_dicts = [
        {
            "value": item.value,
            "type": item.type.value if item.type else None,
            "source": item.source_name,
            "severity": item.severity.value,
            "tags": item.tags,
            "reference_url": item.reference_url,
            "reported_at": item.reported_at.isoformat() if item.reported_at else None,
        }
        for item in payload
    ]

    pipeline = CTIPipeline()
    processed = await pipeline.process_and_score(raw_dicts)
    if processed:
        await pipeline.persist_to_database(session, processed)

    return {
        "status": "success",
        "submitted": len(payload),
        "processed": len(processed),
        "message": f"Successfully processed and scored {len(processed)} indicators.",
    }


@router.get(
    "/stats",
    summary="Get Indicator Database Statistics",
    description="Aggregate metrics on stored indicators including tier distribution, type breakdown, and whitelist counts.",
)
async def get_indicator_stats(
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Return high-level operational statistics for SOC dashboard."""
    # Total count
    total_res = await session.execute(select(func.count(IndicatorModel.id)))
    total_count = total_res.scalar() or 0

    # Whitelisted count
    wl_res = await session.execute(
        select(func.count(IndicatorModel.id)).where(IndicatorModel.is_whitelisted.is_(True))
    )
    whitelisted_count = wl_res.scalar() or 0

    # Type breakdown
    type_res = await session.execute(
        select(IndicatorModel.type, func.count(IndicatorModel.id)).group_by(IndicatorModel.type)
    )
    type_counts = {str(row[0]): int(row[1]) for row in type_res.all()}

    # Average confidence score
    avg_res = await session.execute(select(func.avg(IndicatorModel.confidence_score)))
    avg_score = avg_res.scalar() or 0.0

    # Severity distribution
    sev_res = await session.execute(
        select(IndicatorModel.severity, func.count(IndicatorModel.id)).group_by(IndicatorModel.severity)
    )
    severity_counts = {str(row[0]): int(row[1]) for row in sev_res.all()}

    return {
        "total_indicators": total_count,
        "whitelisted_indicators": whitelisted_count,
        "active_threat_indicators": total_count - whitelisted_count,
        "average_confidence_score": round(float(avg_score), 2),
        "indicators_by_type": type_counts,
        "indicators_by_severity": severity_counts,
    }


@router.get(
    "/indicators/types/summary",
    summary="Get Indicator Taxonomy Breakdown Summary",
    description="Detailed operational taxonomy breakdown per IoC type including average confidence and whitelist rates.",
)
async def get_indicator_types_summary(
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Return metrics aggregated per indicator type."""
    stmt = (
        select(
            IndicatorModel.type,
            func.count(IndicatorModel.id).label("total"),
            func.avg(IndicatorModel.confidence_score).label("avg_score"),
            func.max(IndicatorModel.confidence_score).label("max_score"),
            func.sum(case((IndicatorModel.is_whitelisted.is_(True), 1), else_=0)).label("whitelisted"),
        )
        .group_by(IndicatorModel.type)
        .order_by(func.count(IndicatorModel.id).desc())
    )
    result = await session.execute(stmt)
    rows = result.all()

    breakdown = {}
    for r in rows:
        ioc_type = str(r[0])
        total = int(r[1])
        avg_score = round(float(r[2] or 0.0), 2)
        max_score = round(float(r[3] or 0.0), 2)
        whitelisted = int(r[4] or 0)
        breakdown[ioc_type] = {
            "total": total,
            "active": total - whitelisted,
            "whitelisted": whitelisted,
            "avg_confidence": avg_score,
            "max_confidence": max_score,
        }

    return {"summary": breakdown}


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


class SimulationRequest(BaseModel):
    initial_score: float = Field(80.0, ge=0.0, le=100.0)
    ioc_type: str = Field("ipv4", description="Indicator type (ipv4, domain, url, sha256)")
    age_days: float = Field(7.0, ge=0.0, description="Age in days for Weibull survival decay")
    measurements: List[float] = Field(default_factory=lambda: [70.0, 75.0, 85.0, 90.0], description="Sequential sensor scores for Kalman filtering")
    current_state: str = Field("active", description="Current Markov threat state (dormant, active, monitored, remediated)")


class SimulationResponse(BaseModel):
    weibull_decayed_score: float
    weibull_survival_prob: float
    kalman_filtered_score: float
    kalman_variance: float
    markov_next_probabilities: Dict[str, float]


@router.post(
    "/scoring/simulate",
    response_model=SimulationResponse,
    summary="Simulate Mathematical Threat State & Reliability Models",
    description="Run Weibull survival decay, Kalman filter score convergence, and Markov state transition predictions.",
)
async def simulate_scoring(payload: SimulationRequest) -> SimulationResponse:
    """Run mathematical scoring models simulation."""
    decayed = WeibullReliabilityModel.calculate_weibull_decayed_score(
        initial_score=payload.initial_score,
        age_days=payload.age_days,
        ioc_type=payload.ioc_type,
    )
    survival = WeibullReliabilityModel.survival_probability(
        age_days=payload.age_days,
        ioc_type=payload.ioc_type,
    )

    kf = KalmanConfidenceFilter(initial_confidence=payload.initial_score)
    final_score = payload.initial_score
    var = 100.0
    for m in payload.measurements:
        final_score, var = kf.update(m)

    try:
        st = ThreatState(payload.current_state.lower())
    except ValueError:
        st = ThreatState.ACTIVE
    probs = MarkovThreatStateModel.step_probability(st)
    str_probs = {k.value: v for k, v in probs.items()}

    return SimulationResponse(
        weibull_decayed_score=decayed,
        weibull_survival_prob=round(survival, 4),
        kalman_filtered_score=final_score,
        kalman_variance=var,
        markov_next_probabilities=str_probs,
    )


class BetaScoringRequest(BaseModel):
    malicious_count: int = Field(5, ge=0, description="Count of corroborating malicious reports")
    benign_count: int = Field(0, ge=0, description="Count of benign/whitelist counter-evidence reports")
    prior_alpha: float = Field(1.0, ge=0.1, description="Prior Beta alpha parameter")
    prior_beta: float = Field(4.0, ge=0.1, description="Prior Beta beta parameter")


class BetaScoringResponse(BaseModel):
    alpha: float
    beta: float
    posterior_probability: float
    epistemic_variance: float
    confidence_score: float


@router.post(
    "/scoring/beta-distribution",
    response_model=BetaScoringResponse,
    summary="Compute Beta-Binomial Bayesian Threat Confidence",
    description="Calculate exact posterior mean and epistemic variance from evidence counts.",
)
async def compute_beta_distribution(payload: BetaScoringRequest) -> BetaScoringResponse:
    """Calculate conjugate Beta posterior threat score."""
    res = BetaDistributionScorer.calculate_score(
        malicious_count=payload.malicious_count,
        benign_count=payload.benign_count,
        prior_alpha=payload.prior_alpha,
        prior_beta=payload.prior_beta,
    )
    return BetaScoringResponse(**res)


