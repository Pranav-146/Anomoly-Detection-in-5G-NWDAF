"""In-memory trust and risk repository for Stage 2 subscribers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from contextual_risk_assessment import RiskAssessment, RiskLevel


class TrustLevel(str, Enum):
    """Deterministic trust states maintained in memory by the TRR."""

    TRUSTED = "TRUSTED"
    NORMAL = "NORMAL"
    WATCHLIST = "WATCHLIST"
    BLOCKED = "BLOCKED"


@dataclass
class TrustRecord:
    """Current trust state for a single subscriber."""

    supi: str
    trust_level: TrustLevel = TrustLevel.TRUSTED
    latest_risk_level: Optional[RiskLevel] = None
    latest_risk_score: int = 0
    reputation_score: float = 0.0
    consecutive_failures: int = 0
    total_auth_attempts: int = 0
    last_updated: float = 0.0
    history: list[dict[str, Any]] = field(default_factory=list)


class TrustRiskRepository:
    """Lightweight, deterministic in-memory repository for subscriber trust state."""

    def __init__(
        self,
        watchlist_threshold: int = 1,
        block_threshold: int = 2,
        max_history: int = 10,
    ) -> None:
        self.watchlist_threshold = watchlist_threshold
        self.block_threshold = block_threshold
        self.max_history = max_history
        self._records: dict[str, TrustRecord] = {}

    def create_record(self, supi: str) -> TrustRecord:
        """Create a new trust record for a subscriber if one does not yet exist."""
        if supi in self._records:
            return self._records[supi]

        record = TrustRecord(supi=supi)
        self._records[supi] = record
        return record

    def update_from_assessment(self, assessment: RiskAssessment) -> TrustRecord:
        """Update or create the trust record from a RiskAssessment."""
        record = self.create_record(assessment.supi)
        record.total_auth_attempts += 1
        record.last_updated = assessment.timestamp
        record.latest_risk_level = assessment.risk_level
        record.latest_risk_score = assessment.risk_score

        if assessment.risk_level == RiskLevel.HIGH:
            record.consecutive_failures += 1
        else:
            record.consecutive_failures = 0

        if assessment.risk_level == RiskLevel.LOW:
            record.reputation_score = max(0.0, min(1.0, record.reputation_score + 0.05))
        elif assessment.risk_level == RiskLevel.MEDIUM:
            record.reputation_score = max(0.0, min(1.0, record.reputation_score + 0.01))
        else:
            record.reputation_score = max(0.0, min(1.0, record.reputation_score - 0.05))

        history_entry = {
            "timestamp": assessment.timestamp,
            "risk_level": assessment.risk_level.value,
            "risk_score": assessment.risk_score,
            "reasons": list(assessment.reasons),
        }
        record.history.append(history_entry)
        if len(record.history) > self.max_history:
            record.history = record.history[-self.max_history :]

        record.trust_level = self._resolve_trust_level(record)
        return record

    def get_record(self, supi: str) -> Optional[TrustRecord]:
        """Return the current trust record for a subscriber if it exists."""
        return self._records.get(supi)

    def record_exists(self, supi: str) -> bool:
        """Return whether a subscriber record exists in the repository."""
        return supi in self._records

    def export_json(self) -> str:
        """Serialize the current repository contents to JSON."""
        payload = []
        for supi in sorted(self._records):
            record = self._records[supi]
            payload.append(
                {
                    "supi": record.supi,
                    "trust_level": record.trust_level.value,
                    "latest_risk_level": record.latest_risk_level.value if record.latest_risk_level else None,
                    "latest_risk_score": record.latest_risk_score,
                    "reputation_score": record.reputation_score,
                    "consecutive_failures": record.consecutive_failures,
                    "total_auth_attempts": record.total_auth_attempts,
                    "last_updated": record.last_updated,
                    "history": record.history,
                }
            )
        return json.dumps(payload, indent=2)

    def clear(self) -> None:
        """Remove all records from the repository."""
        self._records.clear()

    def _resolve_trust_level(self, record: TrustRecord) -> TrustLevel:
        if record.consecutive_failures >= self.block_threshold:
            return TrustLevel.BLOCKED
        if record.latest_risk_level == RiskLevel.HIGH:
            return TrustLevel.WATCHLIST
        if record.latest_risk_level == RiskLevel.MEDIUM:
            return TrustLevel.NORMAL
        return TrustLevel.TRUSTED
