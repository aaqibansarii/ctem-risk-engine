"""
CVSS base score ingestion. Both sources are free, no paid tier:

  1. CIRCL Vulnerability-Lookup (primary) - no API key.
     https://vulnerability.circl.lu/api/vulnerability/{cve}
  2. NVD API 2.0 (fallback) - free, no key required for basic use.
     https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}

Live fetch every call - no cache. Returns (score, source) so callers can
record cvss_source ("circl" / "nvd" / "unknown") in the output.
"""
import logging
from typing import Optional

import httpx

from app.config import settings

logger = logging.getLogger("threatgraph.cvss")


def _extract_cvss_from_circl(data: dict) -> Optional[float]:
    for key in ("cvss4_0", "cvss3_1", "cvss3_0", "cvss", "cvssV3_1", "cvssV3_0"):
        val = data.get(key)
        if isinstance(val, (int, float)):
            return float(val)
        if isinstance(val, dict) and "baseScore" in val:
            return float(val["baseScore"])

    metrics = data.get("cveMetadata", {}).get("metrics") or data.get("metrics")
    if isinstance(metrics, dict):
        for metric_list in metrics.values():
            if isinstance(metric_list, list) and metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                if "baseScore" in cvss_data:
                    return float(cvss_data["baseScore"])
    return None


def _fetch_from_circl(cve: str) -> Optional[float]:
    resp = httpx.get(f"{settings.CIRCL_CVE_URL}/{cve}", timeout=15.0)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return _extract_cvss_from_circl(resp.json())


def _extract_cvss_from_nvd(data: dict) -> Optional[float]:
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None
    metrics = vulnerabilities[0].get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            return float(entries[0]["cvssData"]["baseScore"])
    return None


def _fetch_from_nvd(cve: str) -> Optional[float]:
    headers = {"apiKey": settings.NVD_API_KEY} if settings.NVD_API_KEY else {}
    resp = httpx.get(settings.NVD_CVE_URL, params={"cveId": cve}, headers=headers, timeout=20.0)
    resp.raise_for_status()
    return _extract_cvss_from_nvd(resp.json())


def get_cvss_score(cve: str) -> tuple[Optional[float], str]:
    """Returns (cvss_score_or_None, source) where source is 'circl', 'nvd', or 'unknown'."""
    try:
        score = _fetch_from_circl(cve)
        if score is not None:
            return score, "circl"
    except Exception as exc:
        logger.warning(f"CIRCL CVSS lookup failed for {cve}, trying NVD fallback: {exc}")

    try:
        score = _fetch_from_nvd(cve)
        if score is not None:
            return score, "nvd"
    except Exception as exc:
        logger.error(f"NVD CVSS lookup also failed for {cve}: {exc}")

    return None, "unknown"
