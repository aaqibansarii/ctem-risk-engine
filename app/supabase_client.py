"""
Single shared Supabase client instance, used both to read Team 2's assets
table (read-only) and to read/write our own risk_scores table.
"""
import logging

from supabase import create_client, Client

from app.config import settings

logger = logging.getLogger("threatgraph.supabase")

_client: Client | None = None


def get_supabase() -> Client:
    global _client
    if _client is None:
        if not settings.SUPABASE_KEY:
            logger.warning(
                "SUPABASE_KEY is empty - requests to Supabase will fail until it's set "
                "in .env (request it from Team 2)."
            )
        _client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
    return _client
