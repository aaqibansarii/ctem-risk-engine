"""
FIRST.org EPSS (Exploit Prediction Scoring System) ingestion.
Public API, no API key required. Live fetch every call - no cache.
"""
import logging
from typing import Optional

import httpx

from app.config import settings

logger = logging.getLogger("threatgraph.epss")


def get_epss_score(cve: str) -> float:
    """
    Returns EPSS score (0.0-1.0). Defaults to 0.0 if the CVE is unknown to
    EPSS or the source is unreachable, so scoring never hard-fails.
    """
    try:
        resp = httpx.get(settings.FIRST_EPSS_URL, params={"cve": cve}, timeout=15.0)
        resp.raise_for_status()
        data = resp.json()
        results = data.get("data", [])
        if not results:
            return 0.0
        return float(results[0]["epss"])
    except Exception as exc:
        logger.error(f"Failed to fetch EPSS score for {cve}: {exc}")
        return 0.0
