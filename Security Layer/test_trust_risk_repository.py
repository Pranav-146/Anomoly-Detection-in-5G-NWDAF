import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from contextual_risk_assessment import RiskAssessment, RiskLevel
from trust_risk_repository import TrustLevel, TrustRiskRepository


class TrustRiskRepositoryTests(unittest.TestCase):
    def test_new_subscriber_creates_trusted_record(self) -> None:
        repo = TrustRiskRepository()

        record = repo.create_record("imsi-1001")

        self.assertEqual(record.supi, "imsi-1001")
        self.assertEqual(record.trust_level, TrustLevel.TRUSTED)
        self.assertTrue(repo.record_exists("imsi-1001"))
        self.assertEqual(record.total_auth_attempts, 0)
        self.assertEqual(record.consecutive_failures, 0)

    def test_low_risk_update_keeps_trusted_state(self) -> None:
        repo = TrustRiskRepository()
        assessment = RiskAssessment(
            supi="imsi-1002",
            risk_level=RiskLevel.LOW,
            risk_score=10,
            detection_source="RULE",
            timestamp=100.0,
            reasons=["low risk"],
        )

        record = repo.update_from_assessment(assessment)

        self.assertEqual(record.trust_level, TrustLevel.TRUSTED)
        self.assertEqual(record.latest_risk_level, RiskLevel.LOW)
        self.assertEqual(record.latest_risk_score, 10)
        self.assertEqual(record.total_auth_attempts, 1)
        self.assertEqual(record.consecutive_failures, 0)
        self.assertEqual(len(record.history), 1)

    def test_medium_risk_update_moves_to_normal(self) -> None:
        repo = TrustRiskRepository()
        assessment = RiskAssessment(
            supi="imsi-1003",
            risk_level=RiskLevel.MEDIUM,
            risk_score=50,
            detection_source="RULE",
            timestamp=110.0,
            reasons=["medium risk"],
        )

        record = repo.update_from_assessment(assessment)

        self.assertEqual(record.trust_level, TrustLevel.NORMAL)
        self.assertEqual(record.latest_risk_level, RiskLevel.MEDIUM)
        self.assertEqual(record.latest_risk_score, 50)
        self.assertEqual(record.total_auth_attempts, 1)

    def test_high_risk_update_moves_to_watchlist(self) -> None:
        repo = TrustRiskRepository()
        assessment = RiskAssessment(
            supi="imsi-1004",
            risk_level=RiskLevel.HIGH,
            risk_score=100,
            detection_source="RULE",
            timestamp=120.0,
            reasons=["high risk"],
        )

        record = repo.update_from_assessment(assessment)

        self.assertEqual(record.trust_level, TrustLevel.WATCHLIST)
        self.assertEqual(record.latest_risk_level, RiskLevel.HIGH)
        self.assertEqual(record.latest_risk_score, 100)
        self.assertEqual(record.consecutive_failures, 1)

    def test_repeated_high_risk_updates_can_block_subscriber(self) -> None:
        repo = TrustRiskRepository(watchlist_threshold=1, block_threshold=2)
        first = RiskAssessment(
            supi="imsi-1005",
            risk_level=RiskLevel.HIGH,
            risk_score=100,
            detection_source="RULE",
            timestamp=130.0,
            reasons=["first high"],
        )
        second = RiskAssessment(
            supi="imsi-1005",
            risk_level=RiskLevel.HIGH,
            risk_score=100,
            detection_source="RULE",
            timestamp=140.0,
            reasons=["second high"],
        )

        repo.update_from_assessment(first)
        record = repo.update_from_assessment(second)

        self.assertEqual(record.trust_level, TrustLevel.BLOCKED)
        self.assertEqual(record.consecutive_failures, 2)

    def test_history_size_is_limited(self) -> None:
        repo = TrustRiskRepository(max_history=2)
        for index, risk_level in enumerate([RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH]):
            assessment = RiskAssessment(
                supi="imsi-1006",
                risk_level=risk_level,
                risk_score=10 + index * 20,
                detection_source="RULE",
                timestamp=150.0 + index,
                reasons=[f"event {index}"],
            )
            repo.update_from_assessment(assessment)

        record = repo.get_record("imsi-1006")
        self.assertIsNotNone(record)
        self.assertEqual(len(record.history), 2)
        self.assertEqual(record.history[0]["risk_level"], RiskLevel.MEDIUM.value)
        self.assertEqual(record.history[1]["risk_level"], RiskLevel.HIGH.value)

    def test_export_json_contains_repository_state(self) -> None:
        repo = TrustRiskRepository()
        assessment = RiskAssessment(
            supi="imsi-1007",
            risk_level=RiskLevel.HIGH,
            risk_score=100,
            detection_source="RULE",
            timestamp=160.0,
            reasons=["export demo"],
        )
        repo.update_from_assessment(assessment)

        payload = json.loads(repo.export_json())

        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["supi"], "imsi-1007")
        self.assertEqual(payload[0]["trust_level"], TrustLevel.WATCHLIST.value)


if __name__ == "__main__":
    unittest.main()
