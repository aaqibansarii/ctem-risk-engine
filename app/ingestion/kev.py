"""
CISA Known Exploited Vulnerabilities (KEV) ingestion.
Public feed, no API key required. Live fetch every call - no cache.
"""
import logging
from typing import Set

import httpx

from app.config import settings

logger = logging.getLogger("threatgraph.kev")


def _fetch_kev_set() -> Set[str]:
    resp = httpx.get(settings.CISA_KEV_URL, timeout=30.0)
    resp.raise_for_status()
    data = resp.json()
    vulnerabilities = data.get("vulnerabilities", [])
    return {v["cveID"] for v in vulnerabilities if "cveID" in v}


def is_kev_listed(cve: str) -> bool:
    try:
        kev_set = _fetch_kev_set()
    except Exception as exc:
        logger.error(f"Failed to fetch CISA KEV feed: {exc}")
        return False
    return cve.upper() in kev_set
