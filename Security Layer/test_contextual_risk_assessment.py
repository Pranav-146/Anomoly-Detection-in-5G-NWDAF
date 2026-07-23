import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from contextual_risk_assessment import (
    CandidateDetection,
    RiskLevel,
    assess_contextual_risk,
)


class ContextualRiskAssessmentTests(unittest.TestCase):

    def test_low_risk(self) -> None:
        candidate = CandidateDetection(
            supi="imsi-1001",
            rule_detector_result=False,
            reputation_score=0.20,
            detection_source="IF",
            failure_ratio=0.10,
            timestamp=100.0,
        )

        assessment = assess_contextual_risk(candidate)

        self.assertEqual(assessment.supi, "imsi-1001")
        self.assertEqual(assessment.risk_level, RiskLevel.LOW)
        self.assertEqual(assessment.risk_score, 0)
        self.assertEqual(assessment.detection_source, "IF")
        self.assertEqual(assessment.timestamp, 100.0)
        self.assertEqual(assessment.reasons, [])

    def test_medium_risk_rule_only(self) -> None:
        candidate = CandidateDetection(
            supi="imsi-1002",
            rule_detector_result=True,
            reputation_score=0.20,
            detection_source="RULE",
            failure_ratio=0.35,
            timestamp=110.0,
        )

        assessment = assess_contextual_risk(candidate)

        self.assertEqual(assessment.risk_level, RiskLevel.MEDIUM)
        self.assertEqual(assessment.risk_score, 50)
        self.assertIn("Rule threshold exceeded", assessment.reasons)

    def test_medium_risk_reputation_only(self) -> None:
        candidate = CandidateDetection(
            supi="imsi-1003",
            rule_detector_result=False,
            reputation_score=0.60,
            detection_source="IF",
            failure_ratio=0.20,
            timestamp=120.0,
        )

        assessment = assess_contextual_risk(candidate)

        self.assertEqual(assessment.risk_level, RiskLevel.MEDIUM)
        self.assertEqual(assessment.risk_score, 50)
        self.assertIn("Reputation score exceeded threshold", assessment.reasons)

    def test_high_risk_rule_and_reputation(self) -> None:
        candidate = CandidateDetection(
            supi="imsi-1004",
            rule_detector_result=True,
            reputation_score=0.70,
            detection_source="BOTH",
            failure_ratio=0.40,
            timestamp=130.0,
        )

        assessment = assess_contextual_risk(candidate)

        self.assertEqual(assessment.risk_level, RiskLevel.HIGH)
        self.assertEqual(assessment.risk_score, 100)
        self.assertIn("Rule threshold exceeded", assessment.reasons)
        self.assertIn("Reputation score exceeded threshold", assessment.reasons)
        self.assertIn("Repeated authentication failures detected", assessment.reasons)


if __name__ == "__main__":
    unittest.main()
