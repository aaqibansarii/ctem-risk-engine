"""
Pydantic schemas defining the standardized JSON I/O contract for Team 3.

<<<<<<< HEAD
AssetContext reflects Team 2's real schema (hostname/fqdn/ip_address instead
of a single asset_id column, network_zone instead of exposure). RiskScoreResult
is the richer output written to Supabase and read by Team 4/5.
=======
AssetContext reflects Team 2's real schema, where callers may identify an
asset by numeric `asset_id`, `hostname`, `fqdn`, or `ip_address`. Team 3
preserves Team 2's raw `network_zone` and also derives its own `exposure`.
RiskScoreResult is the richer output written to Supabase and read by Team 4/5.
>>>>>>> 0ac9c00 (Update Team 3 risk engine)
"""
from typing import Optional, Literal
from datetime import datetime
from pydantic import BaseModel, Field

CriticalityLabel = Literal["low", "medium", "high", "critical"]
ExposureLabel = Literal["restricted", "internal", "internet-facing"]
SeverityTier = Literal["P1", "P2", "P3", "P4"]


# --- Input: asset context, resolved from Team 2's Supabase `assets` table ---

class AssetContext(BaseModel):
    """
<<<<<<< HEAD
    Mirrors Team 2's real asset fields. asset_id is not a column in their
    schema - it's resolved from hostname -> fqdn -> ip_address (first
    non-null wins). network_zone is their raw field, preserved untouched;
    exposure is Team 3's derived label used in scoring.
    """
    asset_id: str = Field(..., examples=["web01"])
=======
    Mirrors Team 2's real asset fields. `asset_id` is the canonical
    identifier used by Team 3 after upstream resolution, even if the incoming
    lookup started as a hostname, FQDN, or IP address. `network_zone` is
    preserved untouched; `exposure` is Team 3's derived scoring label.
    """
    asset_id: str = Field(..., examples=["42", "web01"])
>>>>>>> 0ac9c00 (Update Team 3 risk engine)
    asset_type: Optional[str] = Field(default=None, examples=["server", "subdomain"])
    fqdn: Optional[str] = Field(default=None, examples=["web01.example.com"])
    ip_address: Optional[str] = Field(default=None, examples=["10.0.0.10"])

    # Team 2's stated business-importance label. Passed through untouched -
    # we never overwrite this (see criticality_mismatch instead).
    criticality: CriticalityLabel = Field(default="low")

    # Team 2's raw network position label - preserved as-is.
    network_zone: Optional[str] = Field(default=None, examples=["internal", "internet", "dmz", "restricted"])
    # Team 3's derived label, mapped from network_zone, drives the Reachability multiplier.
    exposure: ExposureLabel = Field(default="restricted")

    environment: Optional[str] = Field(default=None, examples=["production", "staging"])
    source: Optional[str] = Field(default=None, examples=["team2-supabase"])


# --- Input: a single finding/vulnerability to be scored ---

class ScoreRequest(BaseModel):
    asset: AssetContext
    cve: str = Field(..., examples=["CVE-2026-1234"])
    tool: Optional[str] = Field(default=None, examples=["nuclei"])


class BatchScoreRequest(BaseModel):
    items: list[ScoreRequest]


# --- Output: standardized scored result, written to Supabase `risk_scores` ---

class RiskScoreResult(BaseModel):
    id: str  # UUID, generated at scoring time
    asset_id: str
    cve: str
    tool: Optional[str] = None

    # Raw signal inputs (all free/open sources)
    cvss: Optional[float] = None          # None if unknown to CIRCL and NVD
    cvss_source: str = "unknown"           # "circl" / "nvd" / "unknown"
    epss: float
    kev_listed: bool

    # Context passed through from Team 2 (never overwritten by us)
    asset_criticality: CriticalityLabel
    network_zone: Optional[str] = None     # Team 2's raw field, preserved
    exposure: ExposureLabel                # Team 3's derived field

    # Derived multipliers and intermediate formula values (transparency/debugging)
    base_score: float
    exploit_score: float
    asset_weight: float
    reachability_multiplier: float
    blast_radius_multiplier: float
    blast_radius_affected_count: Optional[int] = None  # None until Team 4's graph is live
    blast_radius_source: str  # "stub" or "team4-graph"
    raw_composite: float

    # Final output
    risk_score: float
    tier: SeverityTier
    severity: str
    sla_hours: int
    hard_gated: bool

    # True if our computed tier is more severe than Team 2's stated criticality
    # would suggest - a flag for review, never an overwrite of their field.
    criticality_mismatch: bool

    created_at: datetime
    updated_at: datetime
