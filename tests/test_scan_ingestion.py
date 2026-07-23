"""
Validation for raw scan-result extraction and ingestion helpers.
Run with: python -m tests.test_scan_ingestion
"""
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models import AssetContext
from app.scan_ingestion import score_requests_from_scan_payload


def test_extracts_findings_from_raw_scan_payload():
    sample_path = Path(__file__).resolve().parent.parent / "sample_data" / "sample_raw_findings.json"
    payload = json.loads(sample_path.read_text())

    resolved = {
        "web01": AssetContext(asset_id="42", criticality="high", exposure="internal", network_zone="internal"),
        "db01": AssetContext(asset_id="84", criticality="critical", exposure="restricted", network_zone="restricted"),
    }

    def fake_resolve(identifier: str):
        return resolved[identifier]

    with patch("app.scan_ingestion.resolve_asset_context", side_effect=fake_resolve):
        batch = score_requests_from_scan_payload(payload)

    assert len(batch.items) == 3
    assert batch.items[0].asset.asset_id == "42"
    assert batch.items[0].cve == "CVE-2024-3400"
    assert batch.items[1].asset.asset_id == "84"
    assert batch.items[1].cve == "CVE-2023-44487"
    assert batch.items[2].asset.asset_id == "staging-app"
    assert batch.items[2].cve == "CVE-2021-44228"
    print("PASS: raw scan payload is extracted into ScoreRequest items")


def test_rejects_payload_without_cve():
    try:
        score_requests_from_scan_payload({"findings": [{"asset_id": "web01"}]})
    except ValueError as exc:
        assert "CVE" in str(exc)
        print("PASS: invalid scan payloads without CVEs are rejected")
        return
    raise AssertionError("Expected ValueError for missing CVE")


if __name__ == "__main__":
    test_extracts_findings_from_raw_scan_payload()
    test_rejects_payload_without_cve()
    print("\nAll tests passed.")
