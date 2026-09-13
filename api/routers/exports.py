"""FastAPI router for exporting enforcement feeds (Firewall blocklist, STIX 2.1, DNS RPZ, Snort/Suricata)."""


from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cti_core.database import get_db_session
from cti_core.exporters.dns_rpz_exporter import DNSRPZExporter
from cti_core.exporters.firewall_blocklist import FirewallBlocklistExporter
from cti_core.exporters.rules_exporter import RulesExporter
from cti_core.exporters.stix_exporter import STIXExporter
from cti_core.models.indicator import IndicatorModel

router = APIRouter(prefix="/api/v1/export", tags=["Feed Exports"])


@router.get(
    "/firewall.txt",
    response_class=Response,
    summary="Export Firewall Plaintext IP Blocklist",
    description="Dynamic newline-delimited malicious IP blocklist formatted for iptables, pfSense, Palo Alto EDL, and Fortinet.",
)
async def export_firewall_blocklist(
    min_score: float = Query(70.0, ge=0.0, le=100.0, description="Minimum confidence score threshold"),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    """Stream plaintext newline list of high-confidence malicious IPs."""
    stmt = (
        select(IndicatorModel)
        .where(
            IndicatorModel.type.in_(["ipv4", "ipv6"]),
            IndicatorModel.is_whitelisted.is_(False),
            IndicatorModel.confidence_score >= min_score,
        )
        .order_by(IndicatorModel.confidence_score.desc())
    )
    result = await session.execute(stmt)
    indicators = result.scalars().all()

    content = FirewallBlocklistExporter.export_plaintext(indicators, min_score=min_score)
    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'inline; filename="firewall_blocklist.txt"'},
    )


@router.get(
    "/stix.json",
    response_class=Response,
    summary="Export STIX 2.1 Bundle",
    description="Standardized STIX 2.1 JSON bundle for enterprise SIEM (Splunk, Elastic, Sentinel) and SOAR ingestion.",
)
async def export_stix_bundle(
    min_score: float = Query(50.0, ge=0.0, le=100.0, description="Minimum confidence score threshold"),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    """Stream standardized STIX 2.1 JSON bundle."""
    stmt = (
        select(IndicatorModel)
        .where(
            IndicatorModel.is_whitelisted.is_(False),
            IndicatorModel.confidence_score >= min_score,
        )
        .order_by(IndicatorModel.confidence_score.desc())
    )
    result = await session.execute(stmt)
    indicators = result.scalars().all()

    bundle_json = STIXExporter.export_json(indicators)
    return Response(
        content=bundle_json,
        media_type="application/vnd.oasis.stix+json; version=2.1",
        headers={"Content-Disposition": 'inline; filename="threat_intel_stix21.json"'},
    )


@router.get(
    "/dns-rpz.zone",
    response_class=Response,
    summary="Export DNS Response Policy Zone (RPZ)",
    description="DNS RPZ zone file for automated DNS sinkholing via BIND 9, Pi-hole, and Unbound.",
)
async def export_dns_rpz(
    min_score: float = Query(70.0, ge=0.0, le=100.0, description="Minimum confidence score threshold"),
    zone_name: str = Query("rpz.threat-intel.local", description="RPZ zone name"),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    """Stream BIND 9 DNS Response Policy Zone (RPZ) file."""
    stmt = (
        select(IndicatorModel)
        .where(
            IndicatorModel.type == "domain",
            IndicatorModel.is_whitelisted.is_(False),
            IndicatorModel.confidence_score >= min_score,
        )
        .order_by(IndicatorModel.confidence_score.desc())
    )
    result = await session.execute(stmt)
    indicators = result.scalars().all()

    zone_content = DNSRPZExporter.export_rpz(indicators, zone_name=zone_name, min_score=min_score)
    return Response(
        content=zone_content,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'inline; filename="rpz.zone"'},
    )


@router.get(
    "/suricata.rules",
    response_class=Response,
    summary="Export Suricata IDS/IPS Rules",
    description="Suricata rule file generating alerts and drops for outbound C2 traffic and malicious TLS SNI handshakes.",
)
async def export_suricata_rules(
    min_score: float = Query(75.0, ge=0.0, le=100.0, description="Minimum confidence score threshold"),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    """Stream Suricata IDS/IPS alert rules."""
    stmt = (
        select(IndicatorModel)
        .where(
            IndicatorModel.is_whitelisted.is_(False),
            IndicatorModel.confidence_score >= min_score,
        )
        .order_by(IndicatorModel.confidence_score.desc())
    )
    result = await session.execute(stmt)
    indicators = result.scalars().all()

    rules = RulesExporter.export_suricata(indicators, min_score=min_score)
    return Response(
        content=rules,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'inline; filename="suricata.rules"'},
    )


@router.get(
    "/snort.rules",
    response_class=Response,
    summary="Export Snort IDS/IPS Rules",
    description="Snort rule file detecting outbound connections to scored malicious indicators.",
)
async def export_snort_rules(
    min_score: float = Query(75.0, ge=0.0, le=100.0, description="Minimum confidence score threshold"),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    """Stream Snort IDS/IPS alert rules."""
    stmt = (
        select(IndicatorModel)
        .where(
            IndicatorModel.is_whitelisted.is_(False),
            IndicatorModel.confidence_score >= min_score,
        )
        .order_by(IndicatorModel.confidence_score.desc())
    )
    result = await session.execute(stmt)
    indicators = result.scalars().all()

    rules = RulesExporter.export_snort(indicators, min_score=min_score)
    return Response(
        content=rules,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'inline; filename="snort.rules"'},
    )
