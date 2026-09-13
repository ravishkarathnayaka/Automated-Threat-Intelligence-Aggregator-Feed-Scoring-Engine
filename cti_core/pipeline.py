"""Core Ingestion, Normalization, Enrichment, and Scoring Pipeline."""

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cti_core.collectors.abuseipdb import AbuseIPDBCollector
from cti_core.collectors.cisa_kev import CISAKEVCollector
from cti_core.collectors.urlhaus import URLhausCollector
from cti_core.enrichment.otx_enricher import OTXEnricher
from cti_core.enrichment.virustotal_enricher import VirusTotalEnricher
from cti_core.mock_data import get_synthetic_indicators
from cti_core.models.indicator import IndicatorModel, IndicatorSourceModel, IndicatorType
from cti_core.processors.deduplicator import Deduplicator
from cti_core.processors.normalizer import normalize_indicator
from cti_core.processors.whitelist_filter import WhitelistFilter
from cti_core.scoring.scoring_engine import global_scoring_engine

logger = logging.getLogger(__name__)


class CTIPipeline:
    """Orchestrates ingestion, normalization, filtering, enrichment, scoring, and storage."""

    def __init__(self):
        self.collectors = [
            AbuseIPDBCollector(),
            URLhausCollector(),
            CISAKEVCollector(),
        ]
        self.otx_enricher = OTXEnricher()
        self.vt_enricher = VirusTotalEnricher()
        self.scoring_engine = global_scoring_engine
        self.offline_mode = os.getenv("OFFLINE_MODE", "false").lower() in ("true", "1", "yes")

    async def ingest_raw_records(self, use_live: bool = True) -> List[Dict[str, Any]]:
        """Gather raw indicators from all active collectors or fallback dataset."""
        if not use_live or self.offline_mode:
            logger.info("Pipeline operating in mock/offline mode.")
            return get_synthetic_indicators()

        tasks = [collector.collect() for collector in self.collectors]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        raw_records = []
        for res in results:
            if isinstance(res, list):
                raw_records.extend(res)
            elif isinstance(res, Exception):
                logger.error("Collector task raised error: %s", res)

        if not raw_records:
            logger.warning("No live records fetched; utilizing synthetic fallback.")
            return get_synthetic_indicators()
        return raw_records

    async def process_and_score(
        self,
        raw_records: List[Dict[str, Any]],
        skip_enrichment: bool = False,
    ) -> List[Dict[str, Any]]:
        """Normalize, whitelist-check, deduplicate, enrich, and score indicators."""
        normalized_records: List[Dict[str, Any]] = []

        # 1. Normalization & Format Validation
        for rec in raw_records:
            val = rec.get("value")
            if not val:
                continue
            try:
                exp_type = None
                raw_type = rec.get("type")
                if raw_type:
                    try:
                        exp_type = IndicatorType(raw_type.lower())
                    except ValueError:
                        pass

                detected_type, norm_val, defanged_val = normalize_indicator(val, exp_type)
                rec_copy = dict(rec)
                rec_copy["type"] = detected_type.value
                rec_copy["normalized_value"] = norm_val
                rec_copy["defanged_value"] = defanged_val
                normalized_records.append(rec_copy)
            except ValueError as exc:
                logger.debug("Skipping unparseable indicator '%s': %s", val, exc)
                continue

        # 2. Deduplication & Multi-Feed Merging
        merged_records = Deduplicator.deduplicate_records(normalized_records)

        # 3. Whitelist Evaluation, Enrichment, & Scoring
        processed_records: List[Dict[str, Any]] = []
        for record in merged_records:
            ioc_type = record["type"]
            norm_val = record["normalized_value"]
            sources = record["sources"]
            last_seen = record.get("last_seen")

            # Check whitelist
            is_whitelisted, whitelist_reason = WhitelistFilter.is_whitelisted(ioc_type, norm_val)
            record["is_whitelisted"] = is_whitelisted
            record["whitelist_reason"] = whitelist_reason

            # Enrichment (skipped for whitelisted or if disabled)
            enrichment_data: Dict[str, Any] = {}
            if not is_whitelisted and not skip_enrichment:
                # Run OTX & VT lookups
                otx_task = self.otx_enricher.enrich(ioc_type, norm_val)
                vt_task = self.vt_enricher.enrich(ioc_type, norm_val)
                results = await asyncio.gather(otx_task, vt_task, return_exceptions=True)
                otx_res, vt_res = results[0], results[1]
                if not isinstance(otx_res, BaseException) and otx_res:
                    enrichment_data["otx"] = otx_res
                if not isinstance(vt_res, BaseException) and vt_res:
                    enrichment_data["virustotal"] = vt_res

            record["enrichment_data"] = enrichment_data

            # Calculate composite confidence score
            score_breakdown = self.scoring_engine.calculate_score(
                ioc_type=ioc_type,
                value=norm_val,
                sources=sources,
                last_seen=last_seen,
                enrichment_data=enrichment_data,
            )
            record["confidence_score"] = score_breakdown.final_score
            record["score_breakdown"] = score_breakdown.model_dump()
            record["confidence_tier"] = score_breakdown.tier.value

            processed_records.append(record)

        return processed_records

    async def persist_to_database(
        self,
        session: AsyncSession,
        records: List[Dict[str, Any]],
    ) -> int:
        """Persist or update indicators and source metadata in the database."""
        upserted_count = 0

        for rec in records:
            norm_val = rec["normalized_value"]
            ioc_type = rec["type"]

            # Check if exists
            stmt = select(IndicatorModel).where(
                IndicatorModel.type == ioc_type,
                IndicatorModel.normalized_value == norm_val,
            )
            result = await session.execute(stmt)
            existing: Optional[IndicatorModel] = result.scalars().first()

            if existing:
                existing.value = rec["value"]
                existing.confidence_score = rec["confidence_score"]
                existing.severity = rec["severity"]
                existing.tags = rec["tags"]
                existing.is_whitelisted = rec["is_whitelisted"]
                existing.whitelist_reason = rec["whitelist_reason"]
                existing.last_seen = rec["last_seen"]
                existing.enrichment_data = rec["enrichment_data"]
                existing.score_breakdown = rec["score_breakdown"]
                existing.updated_at = datetime.now(timezone.utc)  # type: ignore

                # Update sources
                existing_source_names = {s.source_name for s in existing.sources}
                for src in rec["sources"]:
                    if src["source_name"] not in existing_source_names:
                        new_source = IndicatorSourceModel(
                            indicator_id=existing.id,
                            source_name=src["source_name"],
                            confidence=src.get("confidence"),
                            reported_at=src["reported_at"],
                            reference_url=src.get("reference_url"),
                            raw_tags=src.get("raw_tags", []),
                        )
                        session.add(new_source)
            else:
                new_indicator = IndicatorModel(
                    value=rec["value"],
                    normalized_value=norm_val,
                    type=ioc_type,
                    confidence_score=rec["confidence_score"],
                    severity=rec["severity"],
                    tags=rec["tags"],
                    is_whitelisted=rec["is_whitelisted"],
                    whitelist_reason=rec["whitelist_reason"],
                    first_seen=rec["first_seen"],
                    last_seen=rec["last_seen"],
                    enrichment_data=rec["enrichment_data"],
                    score_breakdown=rec["score_breakdown"],
                )
                session.add(new_indicator)
                await session.flush()  # Obtain new_indicator.id

                for src in rec["sources"]:
                    source_model = IndicatorSourceModel(
                        indicator_id=new_indicator.id,
                        source_name=src["source_name"],
                        confidence=src.get("confidence"),
                        reported_at=src["reported_at"],
                        reference_url=src.get("reference_url"),
                        raw_tags=src.get("raw_tags", []),
                    )
                    session.add(source_model)

            upserted_count += 1

        await session.commit()
        return upserted_count

    async def run_pipeline(
        self,
        session: AsyncSession,
        use_live: bool = True,
        skip_enrichment: bool = False,
    ) -> Dict[str, Any]:
        """Execute complete pipeline cycle and persist results."""
        start_time = datetime.now(timezone.utc)
        logger.info("Initiating threat intelligence pipeline cycle...")

        raw_records = await self.ingest_raw_records(use_live=use_live)
        processed_records = await self.process_and_score(raw_records, skip_enrichment=skip_enrichment)
        count = await self.persist_to_database(session, processed_records)

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        logger.info("Pipeline cycle completed: %d indicators processed in %.2fs.", count, duration)

        return {
            "status": "success",
            "processed_count": count,
            "duration_seconds": round(duration, 2),
            "timestamp": start_time.isoformat(),
        }


# Global pipeline instance
global_pipeline = CTIPipeline()


async def seed_mock_data_if_empty(session: AsyncSession) -> bool:
    """Seed initial mock dataset if the database is currently empty."""
    stmt = select(IndicatorModel).limit(1)
    res = await session.execute(stmt)
    if res.scalars().first() is None:
        logger.info("Database empty; seeding default synthetic threat intelligence feed...")
        await global_pipeline.run_pipeline(session, use_live=False, skip_enrichment=False)
        return True
    return False
