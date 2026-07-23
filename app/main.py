"""
Team 3 - Vulnerability & Risk Analysis
Risk Scoring Engine - FastAPI entrypoint

No Redis, no NATS, no local Postgres - Supabase (via supabase-py) is the
only datastore, shared with Team 2.

Endpoints:
    POST /scan/risk-score              -> score a single finding (asset context supplied inline)
    POST /scan/risk-score/batch        -> score multiple findings
    POST /scan/risk-score/by-asset-id  -> score using asset context resolved from Team 2/1
<<<<<<< HEAD
=======
    POST /scan/ingest-results          -> extract findings from raw scanner output, score them, store them
>>>>>>> 0ac9c00 (Update Team 3 risk engine)
    GET  /risk-scores/{asset_id}       -> retrieve stored scores for an asset
    GET  /risk-scores                  -> list scores, filterable by severity/tier/criticality_mismatch
    GET  /health                       -> liveness check
"""
import logging
<<<<<<< HEAD
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Query

from app.config import settings
from app.models import ScoreRequest, BatchScoreRequest, RiskScoreResult
from app.risk_engine import score_finding
from app.asset_context import resolve_asset_context
from app.risk_store import save_risk_score, get_scores_for_asset, list_scores
=======
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query

from app.asset_context import resolve_asset_context
from app.config import settings
from app.models import BatchScoreRequest, RiskScoreResult, ScoreRequest
from app.risk_engine import score_finding
from app.risk_store import get_scores_for_asset, list_scores, save_risk_score
from app.scan_ingestion import score_requests_from_scan_payload
>>>>>>> 0ac9c00 (Update Team 3 risk engine)

logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger("threatgraph.main")

app = FastAPI(
    title="ThreatGraph - Risk Scoring Engine",
    description=(
        "Team 3 module: CVSS/EPSS/KEV/Reachability/Blast-Radius composite risk "
        "scoring for assets in Team 2's shared Supabase, output for Team 4/5."
    ),
<<<<<<< HEAD
    version="0.3.0",
)


=======
    version="0.4.0",
)


def _raise_service_unavailable(detail: str, exc: Exception) -> None:
    logger.exception(detail)
    raise HTTPException(status_code=503, detail=detail) from exc


>>>>>>> 0ac9c00 (Update Team 3 risk engine)
@app.on_event("startup")
def on_startup():
    if not settings.SUPABASE_KEY:
        logger.warning(
            "SUPABASE_KEY is not set - requests to Supabase will fail until it's "
            "requested from Team 2 and added to .env."
        )
    logger.info(f"Risk Scoring Engine started in {settings.APP_ENV} mode.")


@app.get("/health")
def health():
<<<<<<< HEAD
    return {"status": "ok", "env": settings.APP_ENV, "time": datetime.utcnow().isoformat()}
=======
    return {"status": "ok", "env": settings.APP_ENV, "time": datetime.now(timezone.utc).isoformat()}
>>>>>>> 0ac9c00 (Update Team 3 risk engine)


@app.post("/scan/risk-score", response_model=RiskScoreResult)
def score_single(request: ScoreRequest):
    result = score_finding(asset=request.asset, cve=request.cve, tool=request.tool)
<<<<<<< HEAD
    save_risk_score(result)
=======
    try:
        save_risk_score(result)
    except Exception as exc:
        _raise_service_unavailable("Failed to persist risk score to Supabase.", exc)
>>>>>>> 0ac9c00 (Update Team 3 risk engine)
    return result


@app.post("/scan/risk-score/batch", response_model=list[RiskScoreResult])
def score_batch(request: BatchScoreRequest):
    results = []
    for item in request.items:
        result = score_finding(asset=item.asset, cve=item.cve, tool=item.tool)
<<<<<<< HEAD
        save_risk_score(result)
=======
        try:
            save_risk_score(result)
        except Exception as exc:
            _raise_service_unavailable("Failed to persist one or more risk scores to Supabase.", exc)
>>>>>>> 0ac9c00 (Update Team 3 risk engine)
        results.append(result)
    return results


@app.post("/scan/risk-score/by-asset-id", response_model=RiskScoreResult)
def score_by_asset_id(asset_id: str, cve: str, tool: Optional[str] = None):
    """
    Convenience endpoint: resolves asset context dynamically from Team 2's
<<<<<<< HEAD
    Supabase `assets` table (matched against hostname/fqdn/ip_address), or
    Team 1 / sample fallback if not found there.
    """
    asset = resolve_asset_context(asset_id)
    result = score_finding(asset=asset, cve=cve, tool=tool)
    save_risk_score(result)
    return result


@app.get("/risk-scores/{asset_id}", response_model=list[RiskScoreResult])
def get_scores_for_asset_endpoint(asset_id: str):
    rows = get_scores_for_asset(asset_id)
=======
    Supabase `assets` table, or Team 1 / sample fallback if not found there.
    """
    asset = resolve_asset_context(asset_id)
    result = score_finding(asset=asset, cve=cve, tool=tool)
    try:
        save_risk_score(result)
    except Exception as exc:
        _raise_service_unavailable("Failed to persist risk score to Supabase.", exc)
    return result


@app.post("/scan/ingest-results", response_model=list[RiskScoreResult])
def ingest_scan_results(payload: dict[str, Any], default_tool: Optional[str] = None):
    """
    Accept raw scanner output, extract CVE findings and asset identifiers,
    score them with the existing engine, and persist them to Supabase.
    """
    try:
        batch = score_requests_from_scan_payload(payload, default_tool=default_tool)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    results = []
    for item in batch.items:
        result = score_finding(asset=item.asset, cve=item.cve, tool=item.tool)
        try:
            save_risk_score(result)
        except Exception as exc:
            _raise_service_unavailable("Failed to persist one or more ingested risk scores to Supabase.", exc)
        results.append(result)
    return results


@app.get("/risk-scores/{asset_id}", response_model=list[RiskScoreResult])
def get_scores_for_asset_endpoint(asset_id: str):
    try:
        rows = get_scores_for_asset(asset_id)
    except Exception as exc:
        _raise_service_unavailable("Failed to read risk scores from Supabase.", exc)
>>>>>>> 0ac9c00 (Update Team 3 risk engine)
    if not rows:
        raise HTTPException(status_code=404, detail=f"No risk scores found for asset_id '{asset_id}'")
    return rows


@app.get("/risk-scores", response_model=list[RiskScoreResult])
def list_scores_endpoint(
    severity: Optional[str] = Query(default=None, description="e.g. critical, high, medium, low"),
    tier: Optional[str] = Query(default=None, description="e.g. P1, P2, P3, P4"),
    criticality_mismatch: Optional[bool] = Query(default=None, description="filter to flagged mismatches only"),
    limit: int = Query(default=100, le=1000),
):
<<<<<<< HEAD
    return list_scores(severity=severity, tier=tier, criticality_mismatch=criticality_mismatch, limit=limit)
=======
    try:
        return list_scores(severity=severity, tier=tier, criticality_mismatch=criticality_mismatch, limit=limit)
    except Exception as exc:
        _raise_service_unavailable("Failed to list risk scores from Supabase.", exc)
>>>>>>> 0ac9c00 (Update Team 3 risk engine)
