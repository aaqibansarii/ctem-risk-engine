"""
Team 3 - Risk Scoring Engine

Composite Risk Score = f(CVSS, EPSS, KEV, Asset_Criticality, Reachability, Blast_Radius)

    Base Score        = CVSS_Base * 10             (0-100; neutral midpoint if CVSS unknown)
    Exploit Likelihood = EPSS * 100                  (0-100)
    KEV Multiplier     = 1.5 if KEV-listed else 1.0
    Asset Weight       = 1.0 / 1.5 / 2.0 / 3.0 by Low/Medium/High/Critical
    Reachability Mult. = 1.0 / 1.5 / 2.5 by Restricted/Internal/Internet-facing
    Blast Radius Mult. = stub 1.0 today

    Composite Score = (Base * Exploit * KEV * AssetWeight * Reachability * BlastRadius)
                       / NORMALIZATION_FACTOR

Tiering (P1-P4) follows the project's rule table - see _determine_tier().

`id` is a deterministic UUID5 derived from (asset_id, cve) - not a random
UUID4 - so re-scoring the same finding upserts the same row in Supabase
(risk_store.py) instead of creating duplicates, which is what makes
created_at/updated_at meaningful over time.
"""
import uuid
from datetime import datetime, timezone

from app.config import settings
from app.models import AssetContext, RiskScoreResult
from app.ingestion.kev import is_kev_listed
from app.ingestion.epss import get_epss_score
from app.ingestion.cvss import get_cvss_score
from app.ingestion.blast_radius import get_blast_radius

_ID_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # fixed namespace, arbitrary but constant

_CRITICALITY_WEIGHTS = {
    "low": settings.CRITICALITY_WEIGHT_LOW,
    "medium": settings.CRITICALITY_WEIGHT_MEDIUM,
    "high": settings.CRITICALITY_WEIGHT_HIGH,
    "critical": settings.CRITICALITY_WEIGHT_CRITICAL,
}

_REACHABILITY_MULTIPLIERS = {
    "restricted": settings.REACHABILITY_RESTRICTED,
    "internal": settings.REACHABILITY_INTERNAL,
    "internet-facing": settings.REACHABILITY_INTERNET_FACING,
}


def _finding_id(asset_id: str, cve: str) -> str:
    return str(uuid.uuid5(_ID_NAMESPACE, f"{asset_id}:{cve.upper()}"))


def _determine_tier(
    epss: float,
    cvss: float | None,
    kev_listed: bool,
    criticality: str,
    exposure: str,
) -> tuple[str, str, bool]:
    """
    P1: KEV-listed OR (High EPSS + Internet-facing + Critical asset)
    P2: (High EPSS + High CVSS) OR Critical asset + internet-facing
    P3: (Medium EPSS + Medium CVSS) OR High asset (compensating controls unknown -> absent)
    P4: everything else
    """
    epss_high = epss >= settings.EPSS_HIGH_THRESHOLD
    epss_medium = settings.EPSS_MEDIUM_THRESHOLD <= epss < settings.EPSS_HIGH_THRESHOLD
    cvss_high = cvss is not None and cvss >= settings.CVSS_HIGH_THRESHOLD
    cvss_medium = cvss is not None and settings.CVSS_MEDIUM_THRESHOLD <= cvss < settings.CVSS_HIGH_THRESHOLD
    internet_facing = exposure == "internet-facing"
    is_critical_asset = criticality == "critical"
    is_high_asset = criticality == "high"

    hard_gated = kev_listed or (epss_high and internet_facing and is_critical_asset)
    if hard_gated:
        return "P1", "critical", True

    if (epss_high and cvss_high) or (is_critical_asset and internet_facing):
        return "P2", "high", False

    if (epss_medium and cvss_medium) or is_high_asset:
        return "P3", "medium", False

    return "P4", "low", False


def score_finding(asset: AssetContext, cve: str, tool: str | None) -> RiskScoreResult:
    epss = get_epss_score(cve)
    kev_listed = is_kev_listed(cve)
    cvss, cvss_source = get_cvss_score(cve)
    blast = get_blast_radius(asset.asset_id)

    asset_weight = _CRITICALITY_WEIGHTS[asset.criticality]
    reachability = _REACHABILITY_MULTIPLIERS[asset.exposure]
    kev_multiplier = settings.KEV_MULT_LISTED if kev_listed else settings.KEV_MULT_NOT_LISTED

    base_score = (cvss if cvss is not None else settings.CVSS_DEFAULT_WHEN_UNKNOWN) * 10
    exploit_score = epss * 100

    raw_composite = (
        base_score
        * exploit_score
        * kev_multiplier
        * asset_weight
        * reachability
        * blast.multiplier
    )
    composite_score = round(min(raw_composite / settings.NORMALIZATION_FACTOR, 100.0), 2)

    tier, severity, hard_gated = _determine_tier(
        epss=epss, cvss=cvss, kev_listed=kev_listed,
        criticality=asset.criticality, exposure=asset.exposure,
    )
    if hard_gated:
        composite_score = 100.0

    criticality_mismatch = (
        tier in settings.CRITICALITY_MISMATCH_TIERS
        and asset.criticality in settings.CRITICALITY_MISMATCH_LABELS
    )

    now = datetime.now(timezone.utc)

    return RiskScoreResult(
        id=_finding_id(asset.asset_id, cve),
        asset_id=asset.asset_id,
        cve=cve.upper(),
        tool=tool,
        cvss=cvss,
        cvss_source=cvss_source,
        epss=epss,
        kev_listed=kev_listed,
        asset_criticality=asset.criticality,
        network_zone=asset.network_zone,
        exposure=asset.exposure,
        base_score=round(base_score, 2),
        exploit_score=round(exploit_score, 2),
        asset_weight=asset_weight,
        reachability_multiplier=reachability,
        blast_radius_multiplier=blast.multiplier,
        blast_radius_affected_count=blast.affected_count,
        blast_radius_source=blast.source,
        raw_composite=round(raw_composite, 2),
        risk_score=composite_score,
        tier=tier,
        severity=severity,
        sla_hours=settings.SLA_HOURS_BY_TIER[tier],
        hard_gated=hard_gated,
        criticality_mismatch=criticality_mismatch,
        created_at=now,   # authoritative value comes from the DB on GET; see risk_store.py
        updated_at=now,
    )
