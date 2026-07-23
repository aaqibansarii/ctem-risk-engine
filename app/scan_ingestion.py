"""
Scan result extraction helpers.

This module adds a thin ingestion layer on top of Team 3's existing scoring
engine. It does not change scanner behavior or scoring behavior; it only
normalizes scanner output into the existing ScoreRequest/BatchScoreRequest
contract so results can be scored and persisted in Supabase.
"""
from __future__ import annotations

from typing import Any

from app.asset_context import resolve_asset_context
from app.models import AssetContext, BatchScoreRequest, ScoreRequest


def _extract_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if isinstance(payload, dict):
        if "items" in payload and isinstance(payload["items"], list):
            if all(isinstance(item, dict) and "asset" in item and ("cve" in item or "cve_id" in item or "cveId" in item)
                   for item in payload["items"]):
                return payload["items"]
        for key in ("findings", "results", "vulnerabilities", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        if "asset" in payload or "asset_id" in payload or "hostname" in payload or "fqdn" in payload or "ip_address" in payload:
            return [payload]

    raise ValueError("Unsupported scan payload shape. Expected a finding object, a list of findings, or an object with items/findings/results.")


def _extract_cve(item: dict[str, Any]) -> str:
    for key in ("cve", "cve_id", "cveId"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().upper()

    references = item.get("references")
    if isinstance(references, list):
        for reference in references:
            if isinstance(reference, str) and reference.upper().startswith("CVE-"):
                return reference.upper()

    raise ValueError("Scan finding is missing a CVE identifier.")


def _extract_tool(item: dict[str, Any], default_tool: str | None) -> str | None:
    for key in ("tool", "scanner", "source"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return default_tool


def _extract_identifier(item: dict[str, Any]) -> str | None:
    asset = item.get("asset")
    if isinstance(asset, dict):
        for key in ("asset_id", "hostname", "fqdn", "ip_address"):
            value = asset.get(key)
            if value is not None and str(value).strip():
                return str(value).strip()

    for key in ("asset_id", "hostname", "fqdn", "ip_address", "host", "target"):
        value = item.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _build_inline_asset_context(item: dict[str, Any]) -> AssetContext | None:
    asset = item.get("asset")
    asset_data = asset if isinstance(asset, dict) else item

    asset_id = _extract_identifier(item)
    if not asset_id:
        return None

    criticality = asset_data.get("criticality")
    exposure = asset_data.get("exposure")
    if not isinstance(criticality, str) or not criticality.strip():
        return None
    if not isinstance(exposure, str) or not exposure.strip():
        return None

    return AssetContext(
        asset_id=str(asset_data.get("asset_id", asset_id)),
        asset_type=asset_data.get("asset_type"),
        fqdn=asset_data.get("fqdn"),
        ip_address=str(asset_data["ip_address"]) if asset_data.get("ip_address") is not None else None,
        criticality=criticality.strip().lower(),
        network_zone=asset_data.get("network_zone"),
        exposure=exposure.strip().lower(),
        environment=asset_data.get("environment"),
        source=asset_data.get("source"),
    )


def score_requests_from_scan_payload(payload: Any, default_tool: str | None = None) -> BatchScoreRequest:
    items = _extract_items(payload)
    score_requests: list[ScoreRequest] = []

    for item in items:
        cve = _extract_cve(item)
        tool = _extract_tool(item, default_tool)

        asset = _build_inline_asset_context(item)
        if asset is None:
            identifier = _extract_identifier(item)
            if not identifier:
                raise ValueError(f"Unable to resolve asset identifier for finding '{cve}'.")
            asset = resolve_asset_context(identifier)

        score_requests.append(ScoreRequest(asset=asset, cve=cve, tool=tool))

    return BatchScoreRequest(items=score_requests)
