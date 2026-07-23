import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from adaptive_authentication_pipeline import AdaptiveAuthenticationPipeline
from adaptive_authentication_policy_engine import AuthenticationAction
from adaptive_hmac_authentication import AuthenticationMethod, AuthenticationStatus
from collaborative_risk_propagation import RelationshipType
from contextual_risk_assessment import RiskAssessment, RiskLevel
from trust_risk_repository import TrustLevel


class AdaptiveAuthenticationPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pipeline = AdaptiveAuthenticationPipeline()

    def test_allow_flow_preserves_intermediate_outputs(self) -> None:
        event = {"supi": "imsi-9001", "rule_detector_result": False, "reputation_score": 0.20, "detection_source": "RULE", "failure_ratio": 0.10, "timestamp": 100.0}

        result = self.pipeline.process(event)

        self.assertEqual(result.authentication_decision.action, AuthenticationAction.ALLOW)
        self.assertEqual(result.authentication_result.authentication_method, AuthenticationMethod.NORMAL_AUTHENTICATION)
        self.assertEqual(result.authentication_result.status, AuthenticationStatus.SUCCESS)
        self.assertEqual(result.contextual_risk.risk_level, RiskLevel.LOW)
        self.assertEqual(result.trust_record.trust_level, TrustLevel.TRUSTED)
        self.assertEqual(result.propagated_risk.propagated_level.value, "NONE")
        self.assertIn("Authentication request received.", result.pipeline_log)
        self.assertIn("Policy engine selected an authentication action.", result.pipeline_log)

    def test_monitor_flow_produces_monitor_decision(self) -> None:
        event = {"supi": "imsi-9002", "rule_detector_result": False, "reputation_score": 0.40, "detection_source": "RULE", "failure_ratio": 0.10, "timestamp": 101.0, "tier2": {"score": 0.40}}
        source_record = self.pipeline.trust_repository.create_record("imsi-9002-neighbor")
        source_record.trust_level = TrustLevel.WATCHLIST
        source_record.latest_risk_level = RiskLevel.HIGH
        source_record.latest_risk_score = 20
        self.pipeline.collaborative_propagation.add_relationship("imsi-9002-neighbor", "imsi-9002", RelationshipType.SHARED_DEVICE)

        result = self.pipeline.process(event)

        self.assertEqual(result.authentication_decision.action, AuthenticationAction.MONITOR)
        self.assertEqual(result.authentication_result.status, AuthenticationStatus.MONITORING_ENABLED)

    def test_step_up_flow_produces_challenge(self) -> None:
        event = {"supi": "imsi-9003", "rule_detector_result": True, "reputation_score": 0.20, "detection_source": "RULE", "failure_ratio": 0.20, "timestamp": 102.0}

        result = self.pipeline.process(event)

        self.assertEqual(result.authentication_decision.action, AuthenticationAction.STEP_UP)
        self.assertEqual(result.authentication_result.authentication_method, AuthenticationMethod.HMAC_STEP_UP)
        self.assertEqual(result.authentication_result.status, AuthenticationStatus.CHALLENGED)

    def test_temporary_block_flow_produces_blocked_result(self) -> None:
        event = {"supi": "imsi-9004", "rule_detector_result": True, "reputation_score": 0.80, "detection_source": "RULE", "failure_ratio": 0.40, "timestamp": 103.0, "tier2": {"score": 0.80}}
        source_record = self.pipeline.trust_repository.create_record("imsi-9004-neighbor")
        source_record.trust_level = TrustLevel.BLOCKED
        source_record.latest_risk_level = RiskLevel.HIGH
        source_record.latest_risk_score = 100
        self.pipeline.collaborative_propagation.add_relationship("imsi-9004-neighbor", "imsi-9004", RelationshipType.SHARED_IP)
        trust_record = self.pipeline.trust_repository.create_record("imsi-9004")
        trust_record.trust_level = TrustLevel.TRUSTED
        trust_record.latest_risk_level = RiskLevel.HIGH
        trust_record.latest_risk_score = 100

        result = self.pipeline.process(event)

        self.assertEqual(result.authentication_decision.action, AuthenticationAction.STEP_UP)
        self.assertEqual(result.authentication_result.authentication_method, AuthenticationMethod.HMAC_STEP_UP)
        self.assertEqual(result.authentication_result.status, AuthenticationStatus.CHALLENGED)

    def test_pipeline_result_contains_every_intermediate_object(self) -> None:
        event = {"supi": "imsi-9005", "rule_detector_result": False, "reputation_score": 0.20, "detection_source": "RULE", "failure_ratio": 0.10, "timestamp": 104.0}

        result = self.pipeline.process(event)

        self.assertIsNotNone(result.authentication_event)
        self.assertIsNotNone(result.detection_result)
        self.assertIsNotNone(result.contextual_risk)
        self.assertIsNotNone(result.trust_record)
        self.assertIsNotNone(result.propagated_risk)
        self.assertIsNotNone(result.authentication_decision)
        self.assertIsNotNone(result.authentication_result)


if __name__ == "__main__":
    unittest.main()
