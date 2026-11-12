"""Staleness/inventory reporting - nothing here mutates anything, it only
reads the existing canary_keys rows and flags upkeep candidates:

- a claimed canary that's never triggered and has sat placed for a long
  time likely means the placement itself is dead (repo deleted, config
  rotated out), not that the canary is doing its job quietly.
- an unclaimed canary aging in the pool just means the pool is bigger than
  current placement demand - worth knowing, but not urgent the way a dead
  claimed placement is.
"""

from datetime import datetime, timezone
from typing import List

from . import iam_lifecycle
from .clients import Clients

DEFAULT_CLAIMED_STALE_DAYS = 90
DEFAULT_UNCLAIMED_AGING_DAYS = 180


def _age_days(iso_timestamp: str, now: datetime) -> float:
    created = datetime.fromisoformat(iso_timestamp)
    return (now - created).total_seconds() / 86400


def stale_report(
    clients: Clients,
    claimed_days: int = DEFAULT_CLAIMED_STALE_DAYS,
    unclaimed_days: int = DEFAULT_UNCLAIMED_AGING_DAYS,
) -> dict:
    now = datetime.now(timezone.utc)

    stale_claimed: List[dict] = [
        item
        for item in iam_lifecycle.list_pool(clients, "claimed")
        if not item.get("last_triggered_at") and _age_days(item["claimed_at"], now) >= claimed_days
    ]
    stale_claimed.sort(key=lambda item: item["claimed_at"])

    aging_unclaimed: List[dict] = [
        item
        for item in iam_lifecycle.list_pool(clients, "unclaimed")
        if _age_days(item["created_at"], now) >= unclaimed_days
    ]
    aging_unclaimed.sort(key=lambda item: item["created_at"])

    return {
        "generated_at": now.isoformat(),
        "claimed_days_threshold": claimed_days,
        "unclaimed_days_threshold": unclaimed_days,
        "stale_claimed": stale_claimed,
        "aging_unclaimed": aging_unclaimed,
    }
