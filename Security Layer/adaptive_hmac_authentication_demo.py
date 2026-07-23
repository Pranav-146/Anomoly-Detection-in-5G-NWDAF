"""Demonstrate deterministic execution of adaptive authentication actions."""

from adaptive_authentication_policy_engine import AuthenticationAction, AuthenticationDecision
from adaptive_hmac_authentication import AdaptiveHMACAuthentication


if __name__ == "__main__":
    engine = AdaptiveHMACAuthentication()

    decisions = [
        AuthenticationDecision("imsi-8001", AuthenticationAction.ALLOW, "HIGH", ["allowed"]),
        AuthenticationDecision("imsi-8002", AuthenticationAction.MONITOR, "MEDIUM", ["monitor"]),
        AuthenticationDecision("imsi-8003", AuthenticationAction.STEP_UP, "HIGH", ["step up"]),
        AuthenticationDecision("imsi-8004", AuthenticationAction.TEMPORARY_BLOCK, "HIGH", ["blocked"]),
    ]

    for decision in decisions:
        result = engine.execute(decision)
        print(f"Subscriber: {result.supi}")
        print(f"Decision: {result.action.value}")
        print(f"Execution Method: {result.authentication_method.value}")
        print(f"Status: {result.status.value}")
        print("Audit Log:")
        for entry in result.audit_log:
            print(f"- {entry}")
        print()
