"""
Central configuration for the Team 3 Risk Scoring Engine.
<<<<<<< HEAD
All values are pulled from environment variables (.env) so nothing is hardcoded.

No Redis, no NATS. Supabase (via supabase-py) is both the source of Team 2's
asset data and the destination for our own risk_scores table.
"""
import os
=======

Load order:
1. Process environment variables
2. `.env` in the project directory
3. Private JSON secrets file outside the project directory

This lets the project be shared without including live Supabase secrets.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

>>>>>>> 0ac9c00 (Update Team 3 risk engine)
from dotenv import load_dotenv

load_dotenv()

<<<<<<< HEAD

class Settings:
    # --- Supabase (shared with Team 2) ---
    # Project URL is public/known; the key must be requested from Team 2
    # directly (per their README) and is NOT committed anywhere.
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "https://eqlolqdgviakidyinwrt.supabase.co")
    SUPABASE_KEY: str = os.getenv("SUPABASE_KEY", "")  # get from Team 2

    # --- External data sources (all free, no paid tiers, no keys required) ---
    CISA_KEV_URL: str = os.getenv(
        "CISA_KEV_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    FIRST_EPSS_URL: str = os.getenv(
        "FIRST_EPSS_URL", "https://api.first.org/data/v1/epss"
    )
    CIRCL_CVE_URL: str = os.getenv(
        "CIRCL_CVE_URL", "https://vulnerability.circl.lu/api/vulnerability"
    )
    NVD_CVE_URL: str = os.getenv(
        "NVD_CVE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"
    )
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")  # optional, free to obtain

    # =========================================================================
    # Composite scoring formula (project spec section 7.4 + Blast Radius)
    #
    #   Base Score          = CVSS_Base * 10   (0-100; defaults to neutral
    #                                            midpoint if CVSS unknown)
    #   Exploit Likelihood   = EPSS * 100        (0-100)
    #   KEV Multiplier       = 1.5 if KEV-listed else 1.0
    #   Asset Weight         = 1.0/1.5/2.0/3.0 by Low/Medium/High/Critical
    #   Reachability Mult.   = 1.0/1.5/2.5 by Restricted/Internal/Internet-facing
    #   Blast Radius Mult.   = stub 1.0 today
    #
    #   Composite = (Base * Exploit * KEV * AssetWeight * Reachability * BlastRadius)
    #               / NORMALIZATION_FACTOR
    # =========================================================================
    CVSS_DEFAULT_WHEN_UNKNOWN: float = float(os.getenv("CVSS_DEFAULT_WHEN_UNKNOWN", "5.0"))

    KEV_MULT_LISTED: float = float(os.getenv("KEV_MULT_LISTED", "1.5"))
    KEV_MULT_NOT_LISTED: float = float(os.getenv("KEV_MULT_NOT_LISTED", "1.0"))

    CRITICALITY_WEIGHT_LOW: float = float(os.getenv("CRITICALITY_WEIGHT_LOW", "1.0"))
    CRITICALITY_WEIGHT_MEDIUM: float = float(os.getenv("CRITICALITY_WEIGHT_MEDIUM", "1.5"))
    CRITICALITY_WEIGHT_HIGH: float = float(os.getenv("CRITICALITY_WEIGHT_HIGH", "2.0"))
    CRITICALITY_WEIGHT_CRITICAL: float = float(os.getenv("CRITICALITY_WEIGHT_CRITICAL", "3.0"))

    REACHABILITY_RESTRICTED: float = float(os.getenv("REACHABILITY_RESTRICTED", "1.0"))
    REACHABILITY_INTERNAL: float = float(os.getenv("REACHABILITY_INTERNAL", "1.5"))
    REACHABILITY_INTERNET_FACING: float = float(os.getenv("REACHABILITY_INTERNET_FACING", "2.5"))

    BLAST_RADIUS_MULT_MAX: float = float(os.getenv("BLAST_RADIUS_MULT_MAX", "3.0"))
    BLAST_RADIUS_MULT_STUB: float = float(os.getenv("BLAST_RADIUS_MULT_STUB", "1.0"))

    EPSS_HIGH_THRESHOLD: float = float(os.getenv("EPSS_HIGH_THRESHOLD", "0.50"))
    EPSS_MEDIUM_THRESHOLD: float = float(os.getenv("EPSS_MEDIUM_THRESHOLD", "0.10"))
    CVSS_HIGH_THRESHOLD: float = float(os.getenv("CVSS_HIGH_THRESHOLD", "7.0"))
    CVSS_MEDIUM_THRESHOLD: float = float(os.getenv("CVSS_MEDIUM_THRESHOLD", "4.0"))

    CRITICALITY_MISMATCH_TIERS = {"P1", "P2"}
    CRITICALITY_MISMATCH_LABELS = {"low", "medium"}

    # Recommended SLA per tier, per project spec section 7.4 table.
    SLA_HOURS_BY_TIER = {"P1": 72, "P2": 168, "P3": 336, "P4": 720}  # 3d / 7d / 14d / 30d
=======
_PRIVATE_SECRETS_PATH = Path(
    os.getenv("TEAM3_SECRETS_FILE", "~/.team3-risk-engine-secrets.json")
).expanduser()


def _load_private_secrets() -> dict[str, Any]:
    if not _PRIVATE_SECRETS_PATH.exists():
        return {}
    try:
        data = json.loads(_PRIVATE_SECRETS_PATH.read_text())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


_PRIVATE_SECRETS = _load_private_secrets()


def _setting(name: str, default: str = "") -> str:
    value = os.getenv(name)
    if value not in (None, ""):
        return value
    private_value = _PRIVATE_SECRETS.get(name)
    if private_value not in (None, ""):
        return str(private_value)
    return default


class Settings:
    PRIVATE_SECRETS_FILE: str = str(_PRIVATE_SECRETS_PATH)

    # --- Supabase (shared with Team 2) ---
    SUPABASE_URL: str = _setting("SUPABASE_URL", "https://eqlolqdgviakidyinwrt.supabase.co")
    SUPABASE_KEY: str = _setting("SUPABASE_KEY", "")

    # --- External data sources (all free, no paid tiers, no keys required) ---
    CISA_KEV_URL: str = _setting(
        "CISA_KEV_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )
    FIRST_EPSS_URL: str = _setting("FIRST_EPSS_URL", "https://api.first.org/data/v1/epss")
    CIRCL_CVE_URL: str = _setting("CIRCL_CVE_URL", "https://vulnerability.circl.lu/api/vulnerability")
    NVD_CVE_URL: str = _setting("NVD_CVE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    NVD_API_KEY: str = _setting("NVD_API_KEY", "")

    # =========================================================================
    # Composite scoring formula
    # =========================================================================
    CVSS_DEFAULT_WHEN_UNKNOWN: float = float(_setting("CVSS_DEFAULT_WHEN_UNKNOWN", "5.0"))

    KEV_MULT_LISTED: float = float(_setting("KEV_MULT_LISTED", "1.5"))
    KEV_MULT_NOT_LISTED: float = float(_setting("KEV_MULT_NOT_LISTED", "1.0"))

    CRITICALITY_WEIGHT_LOW: float = float(_setting("CRITICALITY_WEIGHT_LOW", "1.0"))
    CRITICALITY_WEIGHT_MEDIUM: float = float(_setting("CRITICALITY_WEIGHT_MEDIUM", "1.5"))
    CRITICALITY_WEIGHT_HIGH: float = float(_setting("CRITICALITY_WEIGHT_HIGH", "2.0"))
    CRITICALITY_WEIGHT_CRITICAL: float = float(_setting("CRITICALITY_WEIGHT_CRITICAL", "3.0"))

    REACHABILITY_RESTRICTED: float = float(_setting("REACHABILITY_RESTRICTED", "1.0"))
    REACHABILITY_INTERNAL: float = float(_setting("REACHABILITY_INTERNAL", "1.5"))
    REACHABILITY_INTERNET_FACING: float = float(_setting("REACHABILITY_INTERNET_FACING", "2.5"))

    BLAST_RADIUS_MULT_MAX: float = float(_setting("BLAST_RADIUS_MULT_MAX", "3.0"))
    BLAST_RADIUS_MULT_STUB: float = float(_setting("BLAST_RADIUS_MULT_STUB", "1.0"))

    EPSS_HIGH_THRESHOLD: float = float(_setting("EPSS_HIGH_THRESHOLD", "0.50"))
    EPSS_MEDIUM_THRESHOLD: float = float(_setting("EPSS_MEDIUM_THRESHOLD", "0.10"))
    CVSS_HIGH_THRESHOLD: float = float(_setting("CVSS_HIGH_THRESHOLD", "7.0"))
    CVSS_MEDIUM_THRESHOLD: float = float(_setting("CVSS_MEDIUM_THRESHOLD", "4.0"))

    CRITICALITY_MISMATCH_TIERS = {"P1", "P2"}
    CRITICALITY_MISMATCH_LABELS = {"low", "medium"}
    SLA_HOURS_BY_TIER = {"P1": 72, "P2": 168, "P3": 336, "P4": 720}
>>>>>>> 0ac9c00 (Update Team 3 risk engine)

    @property
    def NORMALIZATION_FACTOR(self) -> float:
        max_base = 100.0
        max_exploit = 100.0
        max_kev = max(self.KEV_MULT_LISTED, self.KEV_MULT_NOT_LISTED)
        max_asset = self.CRITICALITY_WEIGHT_CRITICAL
        max_reach = self.REACHABILITY_INTERNET_FACING
        max_blast = self.BLAST_RADIUS_MULT_MAX
        max_product = max_base * max_exploit * max_kev * max_asset * max_reach * max_blast
<<<<<<< HEAD
        return max_product / 100.0  # composite score tops out at ~100

    # --- Team 1 (discovery) - REST, not on shared Supabase ---
    TEAM1_DISCOVERY_API: str = os.getenv("TEAM1_DISCOVERY_API", "")

    # --- Team 2 (asset inventory) - shared Supabase, queried via supabase-py ---
    TEAM2_ASSETS_TABLE: str = os.getenv("TEAM2_ASSETS_TABLE", "assets")
    # Team 2's real schema has no single "asset_id" column - we resolve an
    # identifier from this ordered list of columns instead (first non-null wins).
    TEAM2_ASSET_ID_COLUMNS = ["hostname", "fqdn", "ip_address"]
    TEAM2_COL_CRITICALITY: str = os.getenv("TEAM2_COL_CRITICALITY", "criticality")
    TEAM2_COL_NETWORK_ZONE: str = os.getenv("TEAM2_COL_NETWORK_ZONE", "network_zone")
    TEAM2_COL_ASSET_TYPE: str = os.getenv("TEAM2_COL_ASSET_TYPE", "asset_type")
    TEAM2_COL_FQDN: str = os.getenv("TEAM2_COL_FQDN", "fqdn")
    TEAM2_COL_IP_ADDRESS: str = os.getenv("TEAM2_COL_IP_ADDRESS", "ip_address")
    TEAM2_COL_HOSTNAME: str = os.getenv("TEAM2_COL_HOSTNAME", "hostname")
    TEAM2_COL_ENVIRONMENT: str = os.getenv("TEAM2_COL_ENVIRONMENT", "environment")

    # Team 2's raw network_zone -> our exposure label. network_zone itself is
    # preserved untouched in our output alongside the derived exposure.
    NETWORK_ZONE_TO_EXPOSURE = {
        "internet": "internet-facing",
        "dmz": "internet-facing",
        "internal": "internal",
        "restricted": "restricted",
    }
    NETWORK_ZONE_DEFAULT_EXPOSURE = "internal"  # used if network_zone is missing/unrecognized

    TEAM2_ASSET_INVENTORY_API: str = os.getenv("TEAM2_ASSET_INVENTORY_API", "")  # optional REST fallback

    # --- Team 4 (attack path / graph) - stubbed until their graph is queryable ---
    TEAM4_GRAPH_API: str = os.getenv("TEAM4_GRAPH_API", "")

    # --- Our own table in the shared Supabase project ---
    RISK_SCORES_TABLE: str = os.getenv("RISK_SCORES_TABLE", "risk_scores")

    # --- App ---
    APP_ENV: str = os.getenv("APP_ENV", "development")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
=======
        return max_product / 100.0

    # --- Team 1 / Team 2 / Team 4 integration ---
    TEAM1_DISCOVERY_API: str = _setting("TEAM1_DISCOVERY_API", "")
    TEAM2_ASSETS_TABLE: str = _setting("TEAM2_ASSETS_TABLE", "assets")
    TEAM2_COL_ASSET_PK: str = _setting("TEAM2_COL_ASSET_PK", "asset_id")
    TEAM2_ASSET_ID_COLUMNS = ["asset_id", "hostname", "fqdn", "ip_address"]
    TEAM2_COL_CRITICALITY: str = _setting("TEAM2_COL_CRITICALITY", "criticality")
    TEAM2_COL_NETWORK_ZONE: str = _setting("TEAM2_COL_NETWORK_ZONE", "network_zone")
    TEAM2_COL_ASSET_TYPE: str = _setting("TEAM2_COL_ASSET_TYPE", "asset_type")
    TEAM2_COL_FQDN: str = _setting("TEAM2_COL_FQDN", "fqdn")
    TEAM2_COL_IP_ADDRESS: str = _setting("TEAM2_COL_IP_ADDRESS", "ip_address")
    TEAM2_COL_HOSTNAME: str = _setting("TEAM2_COL_HOSTNAME", "hostname")
    TEAM2_COL_ENVIRONMENT: str = _setting("TEAM2_COL_ENVIRONMENT", "environment")

    NETWORK_ZONE_TO_EXPOSURE = {
        "internet": "internet-facing",
        "dmz": "internet-facing",
        "external": "internet-facing",
        "internal": "internal",
        "restricted": "restricted",
        "cloud_vpc": "internal",
    }
    NETWORK_ZONE_DEFAULT_EXPOSURE = "internal"

    TEAM2_ASSET_INVENTORY_API: str = _setting("TEAM2_ASSET_INVENTORY_API", "")
    TEAM4_GRAPH_API: str = _setting("TEAM4_GRAPH_API", "")

    # --- Our own table in the shared Supabase project ---
    RISK_SCORES_TABLE: str = _setting("RISK_SCORES_TABLE", "risk_scores")

    # --- App ---
    APP_ENV: str = _setting("APP_ENV", "development")
    LOG_LEVEL: str = _setting("LOG_LEVEL", "INFO")
>>>>>>> 0ac9c00 (Update Team 3 risk engine)


settings = Settings()
