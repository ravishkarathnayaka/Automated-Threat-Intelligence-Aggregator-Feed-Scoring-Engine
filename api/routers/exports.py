"""FastAPI router for exporting enforcement feeds (Firewall blocklist, STIX 2.1, DNS RPZ, Snort/Suricata)."""

import json

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cti_core.database import get_db_session
from cti_core.exporters.checkpoint_exporter import CheckPointExporter
from cti_core.exporters.cloudflare_exporter import CloudflareWAFExporter
from cti_core.exporters.csv_exporter import CSVExporter
from cti_core.exporters.dns_rpz_exporter import DNSRPZExporter
from cti_core.exporters.elastic_exporter import ElasticExporter
from cti_core.exporters.firewall_blocklist import FirewallBlocklistExporter
from cti_core.exporters.fortinet_exporter import FortinetExporter
from cti_core.exporters.misp_exporter import MISPExporter
from cti_core.exporters.rules_exporter import RulesExporter
from cti_core.exporters.stix_exporter import STIXExporter
from cti_core.exporters.wazuh_exporter import WazuhExporter
from cti_core.exporters.yara_exporter import YARAExporter
from cti_core.exporters.zeek_exporter import ZeekIntelExporter
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


@router.get(
    "/zeek.intel",
    response_class=Response,
    summary="Export Zeek (Bro) Intelligence Feed",
    description="Zeek Intelligence Framework tab-delimited intel file for network security monitoring.",
)
async def export_zeek_intel(
    min_score: float = Query(70.0, ge=0.0, le=100.0, description="Minimum confidence score threshold"),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    """Stream Zeek Intelligence Framework table."""
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

    intel_text = ZeekIntelExporter.export_intel(indicators, min_score=min_score)
    return Response(
        content=intel_text,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'inline; filename="zeek.intel"'},
    )


@router.get(
    "/checkpoint.txt",
    response_class=Response,
    summary="Export Check Point Custom Intelligence Feed",
    description="Check Point Security Gateway external feed blocklist formatted with drop actions.",
)
async def export_checkpoint_feed(
    min_score: float = Query(70.0, ge=0.0, le=100.0, description="Minimum confidence score threshold"),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    """Stream Check Point Security Gateway formatted feed."""
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

    content = CheckPointExporter.export(indicators, min_score=min_score)
    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'inline; filename="checkpoint_feed.txt"'},
    )


@router.get(
    "/fortinet.txt",
    response_class=Response,
    summary="Export Fortinet FortiGate External Threat Feed",
    description="Fortinet FortiOS threat feed format for external blocklist fabric connector.",
)
async def export_fortinet_feed(
    min_score: float = Query(70.0, ge=0.0, le=100.0, description="Minimum confidence score threshold"),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    """Stream Fortinet FortiGate external threat feed."""
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

    content = FortinetExporter.export(indicators, min_score=min_score)
    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'inline; filename="fortinet_feed.txt"'},
    )


@router.get(
    "/cloudflare.json",
    response_class=Response,
    summary="Export Cloudflare WAF IP Access Rules",
    description="Cloudflare API JSON payload for automated IP access rule creation and WAF blocking.",
)
async def export_cloudflare_rules(
    min_score: float = Query(80.0, ge=0.0, le=100.0, description="Minimum confidence score threshold"),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    """Stream Cloudflare WAF IP access rules JSON array."""
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

    content = CloudflareWAFExporter.export_json(indicators, min_score=min_score)
    return Response(
        content=content,
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": 'inline; filename="cloudflare_waf_rules.json"'},
    )


@router.get(
    "/misp.json",
    response_class=Response,
    summary="Export MISP Event JSON Package",
    description="Standard MISP format event containing mapped IoC attributes for threat sharing communities.",
)
async def export_misp_event(
    min_score: float = Query(70.0, ge=0.0, le=100.0, description="Minimum confidence score threshold"),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    """Stream MISP Event JSON bundle."""
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

    misp_payload = MISPExporter.export_event(indicators, min_score=min_score)
    return Response(
        content=json.dumps(misp_payload, indent=2),
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": 'inline; filename="misp_event.json"'},
    )


@router.get(
    "/yara.yar",
    response_class=Response,
    summary="Export YARA File Hash Detection Rules",
    description="Generated YARA ruleset detecting identified cryptographic file hashes (SHA256, MD5, SHA1).",
)
async def export_yara_rules(
    min_score: float = Query(75.0, ge=0.0, le=100.0, description="Minimum confidence score threshold"),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    """Stream YARA rule definition file."""
    stmt = (
        select(IndicatorModel)
        .where(
            IndicatorModel.type.in_(["sha256", "sha1", "md5"]),
            IndicatorModel.is_whitelisted.is_(False),
            IndicatorModel.confidence_score >= min_score,
        )
        .order_by(IndicatorModel.confidence_score.desc())
    )
    result = await session.execute(stmt)
    indicators = result.scalars().all()

    rules = YARAExporter.export_rules(indicators, min_score=min_score)
    return Response(
        content=rules,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'inline; filename="sentinel_hashes.yar"'},
    )


@router.get(
    "/indicators.csv",
    response_class=Response,
    summary="Export Indicators CSV / TSV Report",
    description="Standard tabular CSV or TSV threat export for spreadsheet analysis, Splunk lookup tables, and SIEMs.",
)
async def export_indicators_csv(
    min_score: float = Query(0.0, ge=0.0, le=100.0, description="Minimum confidence score threshold"),
    delimiter: str = Query(",", description="Delimiter character (',' or '\t')"),
    exclude_whitelisted: bool = Query(True, description="Filter out whitelisted indicators"),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    """Stream CSV/TSV indicator table."""
    stmt = (
        select(IndicatorModel)
        .where(IndicatorModel.confidence_score >= min_score)
        .order_by(IndicatorModel.confidence_score.desc())
    )
    result = await session.execute(stmt)
    indicators = result.scalars().all()

    csv_data = CSVExporter.export(
        indicators,
        delimiter=delimiter,
        min_score=min_score,
        exclude_whitelisted=exclude_whitelisted,
    )
    return Response(
        content=csv_data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'inline; filename="indicators_export.csv"'},
    )


@router.get(
    "/elastic.ndjson",
    response_class=Response,
    summary="Export Elasticsearch Bulk NDJSON Threat Feed",
    description="Bulk newline-delimited JSON for direct ingestion into Elasticsearch and OpenSearch indices.",
)
async def export_elastic_ndjson(
    min_score: float = Query(70.0, ge=0.0, le=100.0, description="Minimum confidence score threshold"),
    index_name: str = Query("threat-intel-indicators", description="Target index name"),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    """Stream Elasticsearch bulk NDJSON feed."""
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

    content = ElasticExporter.export_bulk_ndjson(indicators, index_name=index_name, min_score=min_score)
    return Response(
        content=content,
        media_type="application/x-ndjson; charset=utf-8",
        headers={"Content-Disposition": f'inline; filename="{index_name}.ndjson"'},
    )


@router.get(
    "/wazuh.cdb",
    response_class=Response,
    summary="Export Wazuh SIEM CDB Threat List",
    description="Wazuh constant database (CDB) list format (key:value) for instant rule engine lookups.",
)
async def export_wazuh_cdb(
    min_score: float = Query(70.0, ge=0.0, le=100.0, description="Minimum confidence score threshold"),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    """Stream Wazuh SIEM CDB list."""
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

    content = WazuhExporter.export_cdb_list(indicators, min_score=min_score)
    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'inline; filename="sentinel_threats.cdb"'},
    )









