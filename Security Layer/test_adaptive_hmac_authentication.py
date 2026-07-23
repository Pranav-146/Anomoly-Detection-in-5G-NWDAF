import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from adaptive_authentication_policy_engine import AuthenticationAction, AuthenticationDecision
from adaptive_hmac_authentication import AdaptiveHMACAuthentication, AuthenticationMethod, AuthenticationStatus


class AdaptiveHMACAuthenticationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = AdaptiveHMACAuthentication()

    def test_allow_executes_normal_authentication(self) -> None:
        decision = AuthenticationDecision(supi="imsi-7001", action=AuthenticationAction.ALLOW, confidence="HIGH", reasons=["allow"])

        result = self.engine.execute(decision)

        self.assertTrue(result.success)
        self.assertEqual(result.authentication_method, AuthenticationMethod.NORMAL_AUTHENTICATION)
        self.assertEqual(result.status, AuthenticationStatus.SUCCESS)
        self.assertIn("Executing normal authentication flow.", result.audit_log)

    def test_monitor_executes_monitoring_mode(self) -> None:
        decision = AuthenticationDecision(supi="imsi-7002", action=AuthenticationAction.MONITOR, confidence="MEDIUM", reasons=["monitor"])

        result = self.engine.execute(decision)

        self.assertTrue(result.success)
        self.assertEqual(result.authentication_method, AuthenticationMethod.NORMAL_AUTHENTICATION)
        self.assertEqual(result.status, AuthenticationStatus.MONITORING_ENABLED)
        self.assertIn("Monitoring mode enabled.", result.audit_log)

    def test_step_up_executes_hmac_challenge(self) -> None:
        decision = AuthenticationDecision(supi="imsi-7003", action=AuthenticationAction.STEP_UP, confidence="HIGH", reasons=["step up"])

        result = self.engine.execute(decision)

        self.assertTrue(result.success)
        self.assertEqual(result.authentication_method, AuthenticationMethod.HMAC_STEP_UP)
        self.assertEqual(result.status, AuthenticationStatus.CHALLENGED)
        self.assertIn("Executing adaptive HMAC challenge.", result.audit_log)

    def test_temporary_block_executes_block(self) -> None:
        decision = AuthenticationDecision(supi="imsi-7004", action=AuthenticationAction.TEMPORARY_BLOCK, confidence="HIGH", reasons=["blocked"])

        result = self.engine.execute(decision)

        self.assertFalse(result.success)
        self.assertEqual(result.authentication_method, AuthenticationMethod.ACCESS_BLOCKED)
        self.assertEqual(result.status, AuthenticationStatus.TEMPORARILY_BLOCKED)
        self.assertIn("Access temporarily blocked by policy.", result.audit_log)

    def test_module_never_changes_decision(self) -> None:
        decision = AuthenticationDecision(supi="imsi-7005", action=AuthenticationAction.STEP_UP, confidence="HIGH", reasons=["step-up"])

        result = self.engine.execute(decision)

        self.assertEqual(result.supi, decision.supi)
        self.assertEqual(result.action, decision.action)
        self.assertEqual(result.action, AuthenticationAction.STEP_UP)
        self.assertEqual(decision.reasons, ["step-up"])


if __name__ == "__main__":
    unittest.main()
