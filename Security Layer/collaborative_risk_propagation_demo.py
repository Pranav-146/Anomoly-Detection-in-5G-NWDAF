"""Demonstrate deterministic collaborative risk propagation."""

from contextual_risk_assessment import RiskLevel
from trust_risk_repository import TrustLevel, TrustRiskRepository
from collaborative_risk_propagation import CollaborativeRiskPropagation, RelationshipType


if __name__ == "__main__":
    repo = TrustRiskRepository()
    crp = CollaborativeRiskPropagation(repo)

    for supi, trust_level, risk_score in [
        ("imsi-4001", TrustLevel.WATCHLIST, 100),
        ("imsi-4002", TrustLevel.BLOCKED, 90),
        ("imsi-4003", TrustLevel.NORMAL, 0),
        ("imsi-4004", TrustLevel.NORMAL, 0),
    ]:
        record = repo.create_record(supi)
        record.trust_level = trust_level
        record.latest_risk_level = RiskLevel.HIGH if trust_level in {TrustLevel.WATCHLIST, TrustLevel.BLOCKED} else RiskLevel.LOW
        record.latest_risk_score = risk_score
        record.last_updated = 1.0

    crp.add_relationship("imsi-4001", "imsi-4003", RelationshipType.SHARED_DEVICE)
    crp.add_relationship("imsi-4002", "imsi-4003", RelationshipType.SHARED_IP)
    crp.add_relationship("imsi-4001", "imsi-4004", RelationshipType.SHARED_SLICE)

    for supi in ["imsi-4003", "imsi-4004"]:
        propagated = crp.calculate_propagated_risk(supi)
        print(f"Subscriber={propagated.supi}")
        print(f"Propagated Score={propagated.propagated_score}")
        print(f"Propagated Level={propagated.propagated_level.value}")
        print(f"Contributing Neighbors={propagated.contributing_neighbors}")
        print(f"Explanation={propagated.explanations[-1]}")
        print()
