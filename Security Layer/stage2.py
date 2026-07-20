"""Contextual risk assessment for Stage 2.

This module is intentionally metadata-only. It runs after Stage 1 has already
produced a candidate detection and records contextual network information for
reporting and audit purposes. It does not attempt any location-based
attribution or attacker identification.
"""

from dataclasses import dataclass


@dataclass
class Stage2Config:
    """Configuration for metadata-only contextual risk assessment."""


def attribute(supi: str, flagged_origin: str, history=None,
              is_fanout_candidate: bool = False,
              cfg: Stage2Config = Stage2Config()) -> dict:
    """Return a neutral contextual assessment for a Stage 1 candidate."""
    return {
        "supi": supi,
        "origin": flagged_origin,
        "target": "supi",
        "reason": "Contextual risk assessment only; no location-based attribution performed",
        "context": {
            "serving_origin": flagged_origin,
        },
    }
