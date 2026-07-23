"""Demonstrate deterministic adaptive authentication policy decisions."""

from adaptive_authentication_policy_engine import AdaptiveAuthenticationPolicyEngine
from collaborative_risk_propagation import PropagatedLevel, PropagatedRisk
from contextual_risk_assessment import RiskLevel
from trust_risk_repository import TrustLevel, TrustRecord


if __name__ == "__main__":
    engine = AdaptiveAuthenticationPolicyEngine()

    cases = [
        ("imsi-6001", TrustLevel.TRUSTED, RiskLevel.LOW, PropagatedLevel.NONE, 0.0),
        ("imsi-6002", TrustLevel.TRUSTED, RiskLevel.LOW, PropagatedLevel.LOW, 10.0),
        ("imsi-6003", TrustLevel.NORMAL, RiskLevel.MEDIUM, PropagatedLevel.NONE, 0.0),
        ("imsi-6004", TrustLevel.WATCHLIST, RiskLevel.LOW, PropagatedLevel.NONE, 0.0),
        ("imsi-6005", TrustLevel.BLOCKED, RiskLevel.HIGH, PropagatedLevel.NONE, 0.0),
    ]

    for supi, trust_level, own_risk, propagated_level, propagated_score in cases:
        trust_record = TrustRecord(supi=supi, trust_level=trust_level, latest_risk_level=own_risk)
        propagated_risk = PropagatedRisk(supi=supi, propagated_score=propagated_score, propagated_level=propagated_level, contributing_neighbors=[], explanations=[])
        decision = engine.evaluate(trust_record, propagated_risk)
        print(f"Subscriber: {decision.supi}")
        print(f"Action: {decision.action.value}")
        print(f"Confidence: {decision.confidence}")
        print("Reasons:")
        for reason in decision.reasons:
            print(f"- {reason}")
        print()
