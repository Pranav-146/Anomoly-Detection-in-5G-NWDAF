"""
trr.py — Trust & Risk Repository.

Holds TEMPORARY, EXPIRING risk entries (never permanent bans). When Stage 2
attributes risk to a SUPI or an origin, an entry is created here. A blocked
identity that successfully completes step-up re-authentication (see
stepup_auth.py) has its entry cleared immediately, before natural expiry.
"""

from dataclasses import dataclass, field
import time


@dataclass
class RiskEntry:
    target_id: str            # SUPI or origin identifier
    target_type: str          # "supi" | "origin"
    risk_level: str           # "high" | "medium"
    detection_source: str     # "tier1" | "tier2" | "stage1b"
    created_at: float
    expiry_seconds: float
    verified: bool = False

    def is_expired(self, now: float) -> bool:
        return now >= self.created_at + self.expiry_seconds


class TrustRiskRepository:
    def __init__(self, default_expiry_seconds: float = 300.0):
        self.entries: dict[str, RiskEntry] = {}
        self.default_expiry_seconds = default_expiry_seconds

    def add_risk(self, target_id: str, target_type: str, risk_level: str,
                 detection_source: str, now: float, expiry_seconds: float = None) -> RiskEntry:
        entry = RiskEntry(
            target_id=target_id, target_type=target_type, risk_level=risk_level,
            detection_source=detection_source, created_at=now,
            expiry_seconds=expiry_seconds or self.default_expiry_seconds,
        )
        self.entries[target_id] = entry
        return entry

    def is_blocked(self, target_id: str, now: float) -> bool:
        entry = self.entries.get(target_id)
        if entry is None:
            return False
        if entry.is_expired(now):
            del self.entries[target_id]
            return False
        return not entry.verified

    def clear_on_verification(self, target_id: str) -> bool:
        """Called when step-up re-auth succeeds. Returns True if an entry was cleared."""
        if target_id in self.entries:
            del self.entries[target_id]
            return True
        return False

    def propagate_snapshot(self, now: float) -> list[dict]:
        """
        Returns the current risk entries as a serializable snapshot, representing
        what would be shared with neighbouring AMFs/cell towers for collaborative
        risk awareness (simulated here as an in-memory broadcast, not an actual
        cross-node network call). `now` must be the same simulated clock used
        elsewhere, not real wall-clock time.
        """
        return [
            {"target_id": e.target_id, "target_type": e.target_type,
             "risk_level": e.risk_level, "source": e.detection_source,
             "expires_in": round(e.created_at + e.expiry_seconds - now, 1)}
            for e in self.entries.values()
        ]


if __name__ == "__main__":
    trr = TrustRiskRepository(default_expiry_seconds=60.0)

    print("=== Add risk entry for a spoofed origin ===")
    trr.add_risk("cellZ_conn_1", "origin", "high", "tier1", now=0.0)
    print("blocked at t=0:", trr.is_blocked("cellZ_conn_1", now=0.0))
    assert trr.is_blocked("cellZ_conn_1", now=0.0) == True
    print("PASS\n")

    print("=== Successful step-up re-auth clears the entry immediately ===")
    cleared = trr.clear_on_verification("cellZ_conn_1")
    print("cleared:", cleared)
    print("blocked after clearing:", trr.is_blocked("cellZ_conn_1", now=1.0))
    assert trr.is_blocked("cellZ_conn_1", now=1.0) == False
    print("PASS\n")

    print("=== Entry expires naturally if never cleared ===")
    trr.add_risk("some_supi", "supi", "medium", "tier2", now=0.0)
    blocked_before_expiry = trr.is_blocked("some_supi", now=30.0)
    print("blocked at t=30 (before expiry):", blocked_before_expiry)
    assert blocked_before_expiry == True
    blocked_after_expiry = trr.is_blocked("some_supi", now=61.0)
    print("blocked at t=61 (after 60s expiry):", blocked_after_expiry)
    assert blocked_after_expiry == False
    print("PASS\n")

    print("=== Propagation snapshot (simulated cross-AMF sharing) ===")
    trr.add_risk("cellQ_conn_9", "origin", "high", "stage1b", now=100.0)
    print(trr.propagate_snapshot(now=100.0))
