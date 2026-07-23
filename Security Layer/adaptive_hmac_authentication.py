"""Execution-layer adaptive authentication module for policy decisions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from adaptive_authentication_policy_engine import AuthenticationAction, AuthenticationDecision


class AuthenticationMethod(str, Enum):
    """Execution methods used by the authentication engine."""

    NORMAL_AUTHENTICATION = "NORMAL_AUTHENTICATION"
    HMAC_STEP_UP = "HMAC_STEP_UP"
    ACCESS_BLOCKED = "ACCESS_BLOCKED"


class AuthenticationStatus(str, Enum):
    """Status values emitted by the execution engine."""

    SUCCESS = "SUCCESS"
    MONITORING_ENABLED = "MONITORING_ENABLED"
    CHALLENGED = "CHALLENGED"
    TEMPORARILY_BLOCKED = "TEMPORARILY_BLOCKED"


@dataclass
class AuthenticationResult:
    """Result returned after executing an authentication action."""

    supi: str
    action: AuthenticationAction
    success: bool
    authentication_method: AuthenticationMethod
    status: AuthenticationStatus
    audit_log: list[str] = field(default_factory=list)


class AdaptiveHMACAuthentication:
    """Deterministic execution engine that follows a policy decision."""

    def execute(self, decision: AuthenticationDecision) -> AuthenticationResult:
        """Dispatch to the execution method indicated by the policy decision."""
        if decision.action == AuthenticationAction.ALLOW:
            return self.execute_normal_authentication(decision)
        if decision.action == AuthenticationAction.MONITOR:
            return self.execute_monitoring_mode(decision)
        if decision.action == AuthenticationAction.STEP_UP:
            return self.execute_hmac_step_up(decision)
        if decision.action == AuthenticationAction.TEMPORARY_BLOCK:
            return self.execute_temporary_block(decision)
        return self.execute_monitoring_mode(decision)

    def execute_normal_authentication(self, decision: Optional[AuthenticationDecision] = None) -> AuthenticationResult:
        """Execute the normal authentication flow."""
        decision = decision or AuthenticationDecision(supi="unknown", action=AuthenticationAction.ALLOW, confidence="HIGH")
        return AuthenticationResult(
            supi=decision.supi,
            action=decision.action,
            success=True,
            authentication_method=AuthenticationMethod.NORMAL_AUTHENTICATION,
            status=AuthenticationStatus.SUCCESS,
            audit_log=[
                "Authentication request received.",
                "Policy decision received.",
                "Executing normal authentication flow.",
                "Authentication completed successfully.",
            ],
        )

    def execute_monitoring_mode(self, decision: Optional[AuthenticationDecision] = None) -> AuthenticationResult:
        """Execute monitoring-only behavior."""
        decision = decision or AuthenticationDecision(supi="unknown", action=AuthenticationAction.MONITOR, confidence="MEDIUM")
        return AuthenticationResult(
            supi=decision.supi,
            action=decision.action,
            success=True,
            authentication_method=AuthenticationMethod.NORMAL_AUTHENTICATION,
            status=AuthenticationStatus.MONITORING_ENABLED,
            audit_log=[
                "Authentication request received.",
                "Policy decision received.",
                "Monitoring mode enabled.",
                "No immediate authentication challenge executed.",
            ],
        )

    def execute_hmac_step_up(self, decision: Optional[AuthenticationDecision] = None) -> AuthenticationResult:
        """Simulate an HMAC-based step-up challenge."""
        decision = decision or AuthenticationDecision(supi="unknown", action=AuthenticationAction.STEP_UP, confidence="HIGH")
        return AuthenticationResult(
            supi=decision.supi,
            action=decision.action,
            success=True,
            authentication_method=AuthenticationMethod.HMAC_STEP_UP,
            status=AuthenticationStatus.CHALLENGED,
            audit_log=[
                "Authentication request received.",
                "Policy decision received.",
                "Executing adaptive HMAC challenge.",
                "Authentication challenge completed successfully.",
            ],
        )

    def execute_temporary_block(self, decision: Optional[AuthenticationDecision] = None) -> AuthenticationResult:
        """Execute a temporary block response."""
        decision = decision or AuthenticationDecision(supi="unknown", action=AuthenticationAction.TEMPORARY_BLOCK, confidence="HIGH")
        return AuthenticationResult(
            supi=decision.supi,
            action=decision.action,
            success=False,
            authentication_method=AuthenticationMethod.ACCESS_BLOCKED,
            status=AuthenticationStatus.TEMPORARILY_BLOCKED,
            audit_log=[
                "Authentication request received.",
                "Policy decision received.",
                "Access temporarily blocked by policy.",
                "No authentication performed.",
            ],
        )
