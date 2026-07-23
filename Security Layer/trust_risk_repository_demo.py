"""Demonstrate the in-memory trust and risk repository."""

from contextual_risk_assessment import RiskAssessment, RiskLevel
from trust_risk_repository import TrustRiskRepository


if __name__ == "__main__":
    repo = TrustRiskRepository()

    assessments = [
        RiskAssessment("imsi-2001", RiskLevel.LOW, 10, "RULE", 100.0, ["low"]),
        RiskAssessment("imsi-2002", RiskLevel.MEDIUM, 50, "RULE", 110.0, ["medium"]),
        RiskAssessment("imsi-2003", RiskLevel.HIGH, 100, "RULE", 120.0, ["high"]),
        RiskAssessment("imsi-2003", RiskLevel.HIGH, 100, "RULE", 130.0, ["repeat high"]),
    ]

    for assessment in assessments:
        repo.update_from_assessment(assessment)

    for supi in ["imsi-2001", "imsi-2002", "imsi-2003"]:
        record = repo.get_record(supi)
        if record is None:
            continue
        print(f"SUPI={record.supi}")
        print(f"Trust Level={record.trust_level.value}")
        print(f"Latest Risk={record.latest_risk_level.value if record.latest_risk_level else 'NONE'}")
        print(f"Reputation={record.reputation_score}")
        print(f"Failure Count={record.consecutive_failures}")
        print(f"History Size={len(record.history)}")
        print()
