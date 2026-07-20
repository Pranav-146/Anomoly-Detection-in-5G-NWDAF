import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from security_gate import DecisionGate, GateDecision, PolicyEngine


class SecurityGateTests(unittest.TestCase):
    def test_tier_boundaries(self):
        gate = DecisionGate()
        decision = gate.evaluate_window(
            supi="imsi-001",
            observed_ratio=0.29,
            baseline_ratio=0.05,
            window_index=0,
            existing_score=0.0,
        )
        self.assertEqual(decision.tier, "re_challenge")

        decision2 = gate.evaluate_window(
            supi="imsi-001",
            observed_ratio=0.29,
            baseline_ratio=0.05,
            window_index=1,
            existing_score=0.63,
        )
        self.assertEqual(decision2.tier, "throttle")

        decision3 = gate.evaluate_window(
            supi="imsi-001",
            observed_ratio=0.29,
            baseline_ratio=0.05,
            window_index=2,
            existing_score=0.89,
        )
        self.assertEqual(decision3.tier, "escalate")

    def test_policy_engine_validation_and_deduplication(self):
        engine = PolicyEngine()
        request = {
            "supi": "imsi-001",
            "exception_id": "campaign-1",
            "tier": "throttle",
            "failure_ratio": 0.29,
            "baseline_ratio": 0.05,
            "excess_ratio": 0.24,
            "reputation_score": 0.65,
        }
        first = engine.handle_request(request)
        self.assertTrue(first["ok"])
        self.assertEqual(first["action"], "admission_throttle")

        duplicate = engine.handle_request(request)
        self.assertFalse(duplicate["ok"])
        self.assertIn("duplicate", duplicate["error"].lower())

        invalid = engine.handle_request({"supi": "", "exception_id": "x", "tier": "throttle"})
        self.assertFalse(invalid["ok"])
        self.assertIn("supi", invalid["error"].lower())


if __name__ == "__main__":
    unittest.main()
