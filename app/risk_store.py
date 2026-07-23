"""
Read/write layer for Team 3's own `risk_scores` table, via supabase-py,
in the same Supabase project as Team 2's tables. We own this table - Team 2's
tables are read-only to us (see app/asset_context.py).

Table is NOT auto-created on startup - run migrations/001_create_risk_scores.sql
manually, once, against Supabase (SQL Editor or psql). This is a shared
project; schema changes should be a deliberate, visible step.
"""
import logging
from typing import Optional

<<<<<<< HEAD
=======
from app.asset_context import canonicalize_asset_identifier
>>>>>>> 0ac9c00 (Update Team 3 risk engine)
from app.config import settings
from app.models import RiskScoreResult
from app.supabase_client import get_supabase

logger = logging.getLogger("threatgraph.risk_store")


def save_risk_score(result: RiskScoreResult) -> None:
    """
    Upserts by `id` (deterministic per asset_id+cve, see risk_engine.py) so
    re-scoring the same finding updates the existing row instead of piling up
    duplicates - this is what makes created_at vs updated_at meaningful.
    created_at is omitted from the payload so the database's DEFAULT NOW()
    only fires on first insert; on an update, the existing created_at is left
    untouched since we don't send a value for it.
    """
    client = get_supabase()
    payload = result.model_dump(mode="json")
    payload.pop("created_at", None)
<<<<<<< HEAD
=======
    payload.pop("updated_at", None)
>>>>>>> 0ac9c00 (Update Team 3 risk engine)
    client.table(settings.RISK_SCORES_TABLE).upsert(payload, on_conflict="id").execute()


def get_scores_for_asset(asset_id: str) -> list[dict]:
    client = get_supabase()
    resp = (
        client.table(settings.RISK_SCORES_TABLE)
        .select("*")
        .eq("asset_id", asset_id)
        .order("risk_score", desc=True)
        .execute()
    )
<<<<<<< HEAD
=======
    rows = resp.data or []
    if rows:
        return rows

    canonical_asset_id = canonicalize_asset_identifier(asset_id)
    if canonical_asset_id == asset_id:
        return []

    resp = (
        client.table(settings.RISK_SCORES_TABLE)
        .select("*")
        .eq("asset_id", canonical_asset_id)
        .order("risk_score", desc=True)
        .execute()
    )
>>>>>>> 0ac9c00 (Update Team 3 risk engine)
    return resp.data or []


def list_scores(
    severity: Optional[str] = None,
    tier: Optional[str] = None,
    criticality_mismatch: Optional[bool] = None,
    limit: int = 100,
) -> list[dict]:
    client = get_supabase()
    query = client.table(settings.RISK_SCORES_TABLE).select("*")
    if severity:
        query = query.eq("severity", severity.lower())
    if tier:
        query = query.eq("tier", tier.upper())
    if criticality_mismatch is not None:
        query = query.eq("criticality_mismatch", criticality_mismatch)
    resp = query.order("risk_score", desc=True).limit(limit).execute()
    return resp.data or []
