"""
Resolves AssetContext for a given asset identifier.

<<<<<<< HEAD
Team 2's real `assets` table (confirmed from their sample record) has no
single `asset_id` column - identity is resolved from hostname -> fqdn ->
ip_address (first match wins). network_zone is their raw field; we map it
to our `exposure` label and preserve network_zone untouched alongside it.
=======
Team 2's `assets` table may expose both a numeric primary key (`asset_id`)
and human-readable identifiers such as `hostname`, `fqdn`, and `ip_address`.
We resolve against those fields in order, map `network_zone` to our
`exposure` label, and preserve the raw `network_zone` alongside it.
>>>>>>> 0ac9c00 (Update Team 3 risk engine)

Resolution order:
  1. Team 2's Supabase `assets` table, queried read-only via supabase-py.
  2. Team 1's discovery API over REST, if configured.
  3. Local sample-data generator, clearly tagged, for standalone testing.

We NEVER write to Team 2's tables - read-only client only.
"""
import logging
import random

import httpx

from app.config import settings
from app.models import AssetContext
from app.supabase_client import get_supabase

logger = logging.getLogger("threatgraph.asset_context")

_SAMPLE_ASSET_TYPES = ["subdomain", "host", "web_app", "server"]
_SAMPLE_CRITICALITIES = ["low", "medium", "high", "critical"]
_SAMPLE_NETWORK_ZONES = ["restricted", "internal", "internet", "dmz"]


def _map_network_zone_to_exposure(network_zone: str | None) -> str:
    if not network_zone:
        return settings.NETWORK_ZONE_DEFAULT_EXPOSURE
    zone = network_zone.strip().lower()
    exposure = settings.NETWORK_ZONE_TO_EXPOSURE.get(zone)
    if exposure is None:
        logger.warning(f"Unrecognized network_zone '{network_zone}' from Team 2 - defaulting exposure.")
        return settings.NETWORK_ZONE_DEFAULT_EXPOSURE
    return exposure


def _normalize_criticality(raw: str | None) -> str:
    if not raw:
        return "low"
    val = raw.strip().lower()
    if val in ("low", "medium", "high", "critical"):
        return val
    logger.warning(f"Unrecognized criticality value '{raw}' from Team 2 - defaulting to 'low'.")
    return "low"


def _row_to_asset_context(row: dict, resolved_id: str) -> AssetContext:
    network_zone = row.get(settings.TEAM2_COL_NETWORK_ZONE)
<<<<<<< HEAD
    return AssetContext(
        asset_id=resolved_id,
=======
    canonical_asset_id = row.get(settings.TEAM2_COL_ASSET_PK)
    return AssetContext(
        asset_id=str(canonical_asset_id) if canonical_asset_id is not None else resolved_id,
>>>>>>> 0ac9c00 (Update Team 3 risk engine)
        asset_type=row.get(settings.TEAM2_COL_ASSET_TYPE),
        fqdn=row.get(settings.TEAM2_COL_FQDN),
        ip_address=row.get(settings.TEAM2_COL_IP_ADDRESS),
        criticality=_normalize_criticality(row.get(settings.TEAM2_COL_CRITICALITY)),
        network_zone=network_zone,
        exposure=_map_network_zone_to_exposure(network_zone),
        environment=row.get(settings.TEAM2_COL_ENVIRONMENT),
        source="team2-supabase",
    )


def _fetch_from_team2_supabase(identifier: str) -> AssetContext | None:
    """
<<<<<<< HEAD
    Tries the identifier against hostname, then fqdn, then ip_address -
    matching Team 2's actual identity model (no single asset_id column).
=======
    Tries the identifier against Team 2's configured identity columns.
    If Team 2 exposes a numeric primary key, we preserve that canonical
    value in the returned AssetContext so downstream writes stay stable.
>>>>>>> 0ac9c00 (Update Team 3 risk engine)
    """
    try:
        client = get_supabase()
    except Exception as exc:
        logger.warning(f"Supabase client unavailable (is SUPABASE_KEY set?): {exc}")
        return None

    for column in settings.TEAM2_ASSET_ID_COLUMNS:
<<<<<<< HEAD
=======
        lookup_value = identifier
        if column == settings.TEAM2_COL_ASSET_PK:
            try:
                lookup_value = int(identifier)
            except ValueError:
                continue

>>>>>>> 0ac9c00 (Update Team 3 risk engine)
        try:
            resp = (
                client.table(settings.TEAM2_ASSETS_TABLE)
                .select("*")
<<<<<<< HEAD
                .eq(column, identifier)
=======
                .eq(column, lookup_value)
>>>>>>> 0ac9c00 (Update Team 3 risk engine)
                .limit(1)
                .execute()
            )
        except Exception as exc:
            logger.warning(
<<<<<<< HEAD
                f"Team 2 Supabase query failed on column '{column}' for '{identifier}' "
=======
                f"Team 2 Supabase query failed on column '{column}' for '{lookup_value}' "
>>>>>>> 0ac9c00 (Update Team 3 risk engine)
                f"(check TEAM2_ASSETS_TABLE / SUPABASE_KEY permissions): {exc}"
            )
            continue

        if resp.data:
            return _row_to_asset_context(resp.data[0], resolved_id=identifier)

    return None


def _fetch_from_team1(asset_id: str) -> AssetContext | None:
    if not settings.TEAM1_DISCOVERY_API:
        return None
    try:
        resp = httpx.get(f"{settings.TEAM1_DISCOVERY_API.rstrip('/')}/assets/{asset_id}", timeout=10.0)
        resp.raise_for_status()
        data = resp.json()
        network_zone = data.get("network_zone")
        return AssetContext(
            asset_id=data.get("asset_id", asset_id),
            asset_type=data.get("asset_type"),
            fqdn=data.get("fqdn"),
            ip_address=data.get("ip_address"),
            criticality=_normalize_criticality(data.get("criticality")),
            network_zone=network_zone,
            exposure=_map_network_zone_to_exposure(network_zone),
            environment=data.get("environment"),
            source="team1-discovery",
        )
    except Exception as exc:
        logger.warning(f"Team 1 discovery lookup failed for {asset_id}: {exc}")
        return None


def _generate_sample_context(asset_id: str) -> AssetContext:
    """Deterministic (seeded by asset_id) sample data - development/testing only."""
    rnd = random.Random(asset_id)
    network_zone = rnd.choice(_SAMPLE_NETWORK_ZONES)
    return AssetContext(
        asset_id=asset_id,
        asset_type=rnd.choice(_SAMPLE_ASSET_TYPES),
        fqdn=f"{asset_id.lower()}.example.com",
        ip_address=f"10.0.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}",
        criticality=rnd.choice(_SAMPLE_CRITICALITIES),
        network_zone=network_zone,
        exposure=_map_network_zone_to_exposure(network_zone),
        environment=rnd.choice(["production", "staging"]),
        source="sample-data-fallback",
    )


<<<<<<< HEAD
def resolve_asset_context(asset_id: str) -> AssetContext:
    """Resolution order: Team 2 Supabase (authoritative) -> Team 1 REST -> sample fallback."""
=======
def resolve_upstream_asset_context(asset_id: str) -> AssetContext | None:
    """Resolve only from real upstream systems, without local sample fallback."""
>>>>>>> 0ac9c00 (Update Team 3 risk engine)
    context = _fetch_from_team2_supabase(asset_id)
    if context is not None:
        return context

    context = _fetch_from_team1(asset_id)
    if context is not None:
        return context

<<<<<<< HEAD
=======
    return None


def canonicalize_asset_identifier(asset_id: str) -> str:
    """
    Returns the canonical upstream asset identifier if Team 2 / Team 1 can
    resolve one. Falls back to the original input unchanged.
    """
    context = resolve_upstream_asset_context(asset_id)
    if context is None:
        return asset_id
    return context.asset_id


def resolve_asset_context(asset_id: str, allow_fallback: bool = True) -> AssetContext:
    """Resolution order: Team 2 Supabase -> Team 1 REST -> optional sample fallback."""
    context = resolve_upstream_asset_context(asset_id)
    if context is not None:
        return context

    if not allow_fallback:
        raise LookupError(f"No upstream asset context found for '{asset_id}'.")

>>>>>>> 0ac9c00 (Update Team 3 risk engine)
    logger.info(f"No upstream data found for {asset_id}; using sample fallback data.")
    return _generate_sample_context(asset_id)
