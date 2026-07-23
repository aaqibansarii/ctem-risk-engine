"""
Standalone validation of the scoring formula, tiering rules, and
criticality-mismatch flag - no live Supabase/network calls required.
Run with: python -m tests.test_risk_engine
"""
import sys
import os
<<<<<<< HEAD
=======
from datetime import datetime, timezone
>>>>>>> 0ac9c00 (Update Team 3 risk engine)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from unittest.mock import patch
<<<<<<< HEAD
from app.models import AssetContext
from app import risk_engine
=======
from fastapi.testclient import TestClient
from app.models import AssetContext, RiskScoreResult
from app import risk_engine
from app.asset_context import _map_network_zone_to_exposure, _row_to_asset_context, canonicalize_asset_identifier
from app import risk_store, main
>>>>>>> 0ac9c00 (Update Team 3 risk engine)


def _score(criticality="low", exposure="restricted", network_zone="restricted", epss=0.02, cvss=3.0, kev=False):
    asset = AssetContext(asset_id="A1", criticality=criticality, exposure=exposure, network_zone=network_zone)
    with patch("app.risk_engine.is_kev_listed", return_value=kev), \
         patch("app.risk_engine.get_epss_score", return_value=epss), \
         patch("app.risk_engine.get_cvss_score", return_value=(cvss, "circl" if cvss is not None else "unknown")):
        return risk_engine.score_finding(asset, "CVE-2024-0001", "nuclei")


def test_kev_forces_p1_regardless_of_other_factors():
    result = _score(criticality="low", exposure="restricted", epss=0.01, cvss=1.0, kev=True)
    assert result.hard_gated is True
    assert result.tier == "P1"
    assert result.risk_score == 100.0
    assert result.sla_hours == 72
    print("PASS: KEV listing forces P1 (SLA 72h) regardless of other factors")


def test_high_epss_internet_facing_critical_forces_p1():
    result = _score(criticality="critical", exposure="internet-facing", epss=0.75, cvss=5.0, kev=False)
    assert result.hard_gated is True
    assert result.tier == "P1"
    print("PASS: High EPSS + internet-facing + critical asset forces P1")


def test_high_epss_high_cvss_gives_p2():
    result = _score(criticality="low", exposure="restricted", epss=0.75, cvss=8.5, kev=False)
    assert result.tier == "P2"
    assert result.sla_hours == 168
    print("PASS: High EPSS + high CVSS -> P2, SLA 168h (7 days)")


def test_low_everything_gives_p4():
    result = _score(criticality="low", exposure="restricted", epss=0.02, cvss=2.0, kev=False)
    assert result.tier == "P4"
    assert result.sla_hours == 720
    print(f"PASS: low-risk finding -> P4, SLA 720h (30 days), score {result.risk_score}")


def test_criticality_mismatch_flagged_not_overwritten():
    result = _score(criticality="low", exposure="restricted", epss=0.01, cvss=1.0, kev=True)
    assert result.criticality_mismatch is True
    assert result.asset_criticality == "low"  # untouched, passed through as-is
    print("PASS: criticality_mismatch flagged without overwriting Team 2's criticality field")


def test_network_zone_preserved_alongside_derived_exposure():
    result = _score(criticality="low", exposure="internet-facing", network_zone="dmz")
    assert result.network_zone == "dmz"       # Team 2's raw field, untouched
    assert result.exposure == "internet-facing"  # Team 3's derived label
    print("PASS: network_zone preserved untouched alongside Team 3's derived exposure")


<<<<<<< HEAD
=======
def test_external_and_cloud_vpc_network_zones_are_mapped():
    assert _map_network_zone_to_exposure("external") == "internet-facing"
    assert _map_network_zone_to_exposure("cloud_vpc") == "internal"
    print("PASS: external/cloud_vpc network zones map to CTEM-compatible exposure labels")


def test_team2_asset_pk_is_used_as_canonical_asset_id():
    row = {
        "asset_id": 42,
        "asset_type": "server",
        "fqdn": "web01.example.com",
        "ip_address": "10.0.0.10",
        "criticality": "high",
        "network_zone": "external",
        "environment": "production",
    }
    context = _row_to_asset_context(row, resolved_id="web01")
    assert context.asset_id == "42"
    assert context.exposure == "internet-facing"
    print("PASS: Team 2 asset primary key is preserved as canonical asset_id when present")


def test_canonicalize_asset_identifier_returns_upstream_pk():
    upstream = AssetContext(asset_id="42", criticality="high", exposure="internal", network_zone="internal")
    with patch("app.asset_context.resolve_upstream_asset_context", return_value=upstream):
        assert canonicalize_asset_identifier("web01") == "42"
    print("PASS: canonicalize_asset_identifier prefers upstream Team 2 asset primary key")


def test_canonicalize_asset_identifier_falls_back_to_input():
    with patch("app.asset_context.resolve_upstream_asset_context", return_value=None):
        assert canonicalize_asset_identifier("web01") == "web01"
    print("PASS: canonicalize_asset_identifier falls back to the original input when no upstream match exists")


def test_get_scores_for_asset_falls_back_to_canonical_identifier():
    class FakeResponse:
        def __init__(self, data):
            self.data = data

    class FakeTable:
        def __init__(self, responses):
            self.responses = responses
            self.lookup_value = None

        def select(self, *_args, **_kwargs):
            return self

        def eq(self, _column, value):
            self.lookup_value = value
            return self

        def order(self, *_args, **_kwargs):
            return self

        def execute(self):
            return FakeResponse(self.responses.get(self.lookup_value, []))

    class FakeClient:
        def __init__(self, responses):
            self.responses = responses

        def table(self, _name):
            return FakeTable(self.responses)

    responses = {
        "web01": [],
        "42": [{"asset_id": "42", "risk_score": 95.0}],
    }
    with patch("app.risk_store.get_supabase", return_value=FakeClient(responses)), \
         patch("app.risk_store.canonicalize_asset_identifier", return_value="42"):
        rows = risk_store.get_scores_for_asset("web01")
    assert len(rows) == 1
    assert rows[0]["asset_id"] == "42"
    print("PASS: score lookup retries with the canonical Team 2 asset identifier when alias lookup is empty")


def test_api_returns_503_when_persistence_fails():
    client = TestClient(main.app)
    payload = {
        "asset": {
            "asset_id": "42",
            "criticality": "high",
            "network_zone": "internal",
            "exposure": "internal",
        },
        "cve": "CVE-2024-0001",
        "tool": "nuclei",
    }
    now = datetime.now(timezone.utc)
    mock_result = RiskScoreResult(
        id="test-id",
        asset_id="42",
        cve="CVE-2024-0001",
        tool="nuclei",
        cvss=8.5,
        cvss_source="circl",
        epss=0.7,
        kev_listed=False,
        asset_criticality="high",
        network_zone="internal",
        exposure="internal",
        base_score=85.0,
        exploit_score=70.0,
        asset_weight=2.0,
        reachability_multiplier=1.5,
        blast_radius_multiplier=1.0,
        blast_radius_affected_count=None,
        blast_radius_source="stub",
        raw_composite=17850.0,
        risk_score=52.89,
        tier="P2",
        severity="high",
        sla_hours=168,
        hard_gated=False,
        criticality_mismatch=False,
        created_at=now,
        updated_at=now,
    )
    with patch("app.main.score_finding", return_value=mock_result), \
         patch("app.main.save_risk_score", side_effect=RuntimeError("supabase down")):
        response = client.post("/scan/risk-score", json=payload)
    assert response.status_code == 503
    assert response.json()["detail"] == "Failed to persist risk score to Supabase."
    print("PASS: API returns a clean 503 when Supabase persistence fails")


>>>>>>> 0ac9c00 (Update Team 3 risk engine)
def test_stable_id_for_same_finding():
    id1 = risk_engine._finding_id("A1", "CVE-2024-0001")
    id2 = risk_engine._finding_id("A1", "CVE-2024-0001")
    id3 = risk_engine._finding_id("A1", "CVE-2024-9999")
    assert id1 == id2
    assert id1 != id3
    print("PASS: finding id is deterministic per (asset_id, cve) - supports upsert, not duplicate rows")


def test_intermediate_fields_present():
    result = _score(cvss=8.0, epss=0.4)
    assert result.base_score == 80.0
    assert result.exploit_score == 40.0
    assert result.raw_composite > 0
    assert result.cvss_source == "circl"
    print("PASS: intermediate formula fields (base_score, exploit_score, raw_composite, cvss_source) populated")


def test_missing_cvss_uses_neutral_default_not_zero():
    with patch("app.risk_engine.get_cvss_score", return_value=(None, "unknown")), \
         patch("app.risk_engine.is_kev_listed", return_value=False), \
         patch("app.risk_engine.get_epss_score", return_value=0.3):
        asset = AssetContext(asset_id="A2", criticality="medium", exposure="internal", network_zone="internal")
        result = risk_engine.score_finding(asset, "CVE-2024-9999", "nuclei")
    assert result.cvss is None
    assert result.cvss_source == "unknown"
    assert result.risk_score > 0
    print(f"PASS: missing CVSS falls back to neutral default, score={result.risk_score}, cvss stays None")


def test_score_never_exceeds_100():
    result = _score(criticality="critical", exposure="internet-facing", epss=1.0, cvss=10.0, kev=True)
    assert result.risk_score <= 100.0
    print(f"PASS: score capped at {result.risk_score} (<=100) even with all factors maxed")


if __name__ == "__main__":
    test_kev_forces_p1_regardless_of_other_factors()
    test_high_epss_internet_facing_critical_forces_p1()
    test_high_epss_high_cvss_gives_p2()
    test_low_everything_gives_p4()
    test_criticality_mismatch_flagged_not_overwritten()
    test_network_zone_preserved_alongside_derived_exposure()
<<<<<<< HEAD
=======
    test_external_and_cloud_vpc_network_zones_are_mapped()
    test_team2_asset_pk_is_used_as_canonical_asset_id()
    test_canonicalize_asset_identifier_returns_upstream_pk()
    test_canonicalize_asset_identifier_falls_back_to_input()
    test_get_scores_for_asset_falls_back_to_canonical_identifier()
    test_api_returns_503_when_persistence_fails()
>>>>>>> 0ac9c00 (Update Team 3 risk engine)
    test_stable_id_for_same_finding()
    test_intermediate_fields_present()
    test_missing_cvss_uses_neutral_default_not_zero()
    test_score_never_exceeds_100()
    print("\nAll tests passed.")
