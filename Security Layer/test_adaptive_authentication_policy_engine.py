import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from adaptive_authentication_policy_engine import AdaptiveAuthenticationPolicyEngine, AuthenticationAction
from collaborative_risk_propagation import PropagatedLevel, PropagatedRisk
from contextual_risk_assessment import RiskLevel
from trust_risk_repository import TrustLevel, TrustRecord


class AdaptiveAuthenticationPolicyEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = AdaptiveAuthenticationPolicyEngine()

    def _make_record(self, supi: str, trust_level: TrustLevel, latest_risk_level: RiskLevel) -> TrustRecord:
        return TrustRecord(supi=supi, trust_level=trust_level, latest_risk_level=latest_risk_level)

    def test_trusted_low_policy_allows(self) -> None:
        decision = self.engine.evaluate(
            self._make_record("imsi-5001", TrustLevel.TRUSTED, RiskLevel.LOW),
            PropagatedRisk("imsi-5001", 0.0, PropagatedLevel.NONE, [], []),
        )

        self.assertEqual(decision.action, AuthenticationAction.ALLOW)
        self.assertEqual(decision.confidence, "HIGH")
        self.assertIn("Trusted subscriber", decision.reasons)

    def test_trusted_low_with_propagated_low_monitors(self) -> None:
        decision = self.engine.evaluate(
            self._make_record("imsi-5002", TrustLevel.TRUSTED, RiskLevel.LOW),
            PropagatedRisk("imsi-5002", 10.0, PropagatedLevel.LOW, ["imsi-5003"], ["Neighbor influence is LOW."]),
        )

        self.assertEqual(decision.action, AuthenticationAction.MONITOR)
        self.assertEqual(decision.confidence, "MEDIUM")

    def test_trusted_low_with_propagated_high_steps_up(self) -> None:
        decision = self.engine.evaluate(
            self._make_record("imsi-5003", TrustLevel.TRUSTED, RiskLevel.LOW),
            PropagatedRisk("imsi-5003", 80.0, PropagatedLevel.HIGH, ["imsi-5004"], ["Neighbor influence is HIGH."]),
        )

        self.assertEqual(decision.action, AuthenticationAction.STEP_UP)
        self.assertEqual(decision.confidence, "HIGH")

    def test_normal_medium_steps_up(self) -> None:
        decision = self.engine.evaluate(
            self._make_record("imsi-5004", TrustLevel.NORMAL, RiskLevel.MEDIUM),
            PropagatedRisk("imsi-5004", 0.0, PropagatedLevel.NONE, [], []),
        )

        self.assertEqual(decision.action, AuthenticationAction.STEP_UP)

    def test_watchlist_steps_up(self) -> None:
        decision = self.engine.evaluate(
            self._make_record("imsi-5005", TrustLevel.WATCHLIST, RiskLevel.LOW),
            PropagatedRisk("imsi-5005", 0.0, PropagatedLevel.NONE, [], []),
        )

        self.assertEqual(decision.action, AuthenticationAction.STEP_UP)

    def test_blocked_temporary_blocks(self) -> None:
        decision = self.engine.evaluate(
            self._make_record("imsi-5006", TrustLevel.BLOCKED, RiskLevel.HIGH),
            PropagatedRisk("imsi-5006", 0.0, PropagatedLevel.NONE, [], []),
        )

        self.assertEqual(decision.action, AuthenticationAction.TEMPORARY_BLOCK)

    def test_own_high_steps_up(self) -> None:
        decision = self.engine.evaluate(
            self._make_record("imsi-5007", TrustLevel.TRUSTED, RiskLevel.HIGH),
            PropagatedRisk("imsi-5007", 0.0, PropagatedLevel.NONE, [], []),
        )

        self.assertEqual(decision.action, AuthenticationAction.STEP_UP)

    def test_own_high_and_propagated_high_temporary_blocks(self) -> None:
        decision = self.engine.evaluate(
            self._make_record("imsi-5008", TrustLevel.TRUSTED, RiskLevel.HIGH),
            PropagatedRisk("imsi-5008", 90.0, PropagatedLevel.HIGH, ["imsi-5009"], ["Neighbor influence is HIGH."]),
        )

        self.assertEqual(decision.action, AuthenticationAction.TEMPORARY_BLOCK)

    def test_explanation_generation(self) -> None:
        decision = self.engine.evaluate(
            self._make_record("imsi-5010", TrustLevel.WATCHLIST, RiskLevel.MEDIUM),
            PropagatedRisk("imsi-5010", 30.0, PropagatedLevel.LOW, ["imsi-5011"], ["Neighbor influence is LOW."]),
        )

        self.assertIn("Subscriber currently on WATCHLIST.", decision.reasons)
        self.assertIn("Own risk is MEDIUM.", decision.reasons)
        self.assertIn("Neighbor influence is LOW.", decision.reasons)


if __name__ == "__main__":
    unittest.main()
