"""
Blast Radius: "if this asset is compromised, how many other assets/services
are affected." This is a graph-connectivity question that belongs to Team 4's
Attack Path Visualization module (their nodes/edges/relationships graph),
which does not exist yet.

STUB BEHAVIOR (current):
    Always returns a neutral multiplier (1.0) and an unknown count (None).
    This keeps the composite formula's shape correct - the term is present
    and does not silently distort scores - without inventing data we don't have.

SWITCHING TO REAL DATA LATER:
    Set TEAM4_GRAPH_API in .env and implement the query in
    _fetch_from_team4_graph() below. Nothing else in the codebase (formula,
    API contract, Supabase write) needs to change - every consumer of this
    module only ever calls get_blast_radius().
"""
import logging
from typing import NamedTuple, Optional

from app.config import settings

logger = logging.getLogger("threatgraph.blast_radius")


class BlastRadius(NamedTuple):
    multiplier: float          # used directly in the scoring formula
    affected_count: Optional[int]  # raw "N other assets affected" - for display/heatmap use later
    source: str                 # "stub" or "team4-graph", for transparency in output/debugging


def _fetch_from_team4_graph(asset_id: str) -> Optional[BlastRadius]:
    """
    Placeholder for the real implementation once Team 4's graph is queryable.
    Expected to call their graph API (or a shared graph table) and translate
    a raw "number of downstream reachable assets" into a bounded multiplier
    (1.0 .. settings.BLAST_RADIUS_MULT_MAX).
    """
    # Not implemented yet - Team 4's graph module doesn't exist yet.
    return None


def get_blast_radius(asset_id: str) -> BlastRadius:
    if settings.TEAM4_GRAPH_API:
        result = _fetch_from_team4_graph(asset_id)
        if result is not None:
            return result
        logger.warning(f"Team 4 graph configured but lookup failed for {asset_id}; using stub value.")

    return BlastRadius(
        multiplier=settings.BLAST_RADIUS_MULT_STUB,
        affected_count=None,
        source="stub",
    )
