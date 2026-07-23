"""Deterministic policy engine for choosing adaptive authentication actions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from collaborative_risk_propagation import PropagatedLevel, PropagatedRisk
from contextual_risk_assessment import RiskLevel
from trust_risk_repository import TrustLevel, TrustRecord


class AuthenticationAction(str, Enum):
    """Deterministic authentication actions selected by the policy engine."""

    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    STEP_UP = "STEP_UP"
    TEMPORARY_BLOCK = "TEMPORARY_BLOCK"


@dataclass
class AuthenticationDecision:
    """Policy decision for an authentication request."""

    supi: str
    action: AuthenticationAction
    confidence: str
    reasons: list[str] = field(default_factory=list)


class AdaptiveAuthenticationPolicyEngine:
    """Pure decision engine that consumes trust and propagated risk outputs."""

    def __init__(self) -> None:
        self._confidence_high = "HIGH"
        self._confidence_medium = "MEDIUM"
        self._confidence_low = "LOW"

    def evaluate(self, trust_record: Optional[TrustRecord], propagated_risk: Optional[PropagatedRisk]) -> AuthenticationDecision:
        """Evaluate trust and propagation state and select an authentication action."""
        if trust_record is None:
            return AuthenticationDecision(
                supi="unknown",
                action=AuthenticationAction.MONITOR,
                confidence=self._confidence_medium,
                reasons=["No trust record available; monitoring recommended."],
            )

        reasons: list[str] = []
        trust_level = trust_record.trust_level
        own_risk = trust_record.latest_risk_level
        propagated_level = propagated_risk.propagated_level if propagated_risk else PropagatedLevel.NONE
        propagated_score = propagated_risk.propagated_score if propagated_risk else 0.0

        if trust_level == TrustLevel.TRUSTED:
            reasons.append("Trusted subscriber")
        elif trust_level == TrustLevel.NORMAL:
            reasons.append("Subscriber is operating at normal trust")
        elif trust_level == TrustLevel.WATCHLIST:
            reasons.append("Subscriber currently on WATCHLIST.")
        elif trust_level == TrustLevel.BLOCKED:
            reasons.append("Subscriber is BLOCKED.")

        if own_risk == RiskLevel.LOW:
            reasons.append("Own risk is LOW.")
        elif own_risk == RiskLevel.MEDIUM:
            reasons.append("Own risk is MEDIUM.")
        elif own_risk == RiskLevel.HIGH:
            reasons.append("Own risk is HIGH.")

        if propagated_level == PropagatedLevel.NONE:
            reasons.append("No propagated threat.")
        elif propagated_level == PropagatedLevel.LOW:
            reasons.append("Neighbor influence is LOW.")
        elif propagated_level == PropagatedLevel.MEDIUM:
            reasons.append("Neighbor influence is MEDIUM.")
        elif propagated_level == PropagatedLevel.HIGH:
            reasons.append("Neighbor influence is HIGH.")

        if trust_level == TrustLevel.BLOCKED:
            return AuthenticationDecision(
                supi=trust_record.supi,
                action=AuthenticationAction.TEMPORARY_BLOCK,
                confidence=self._confidence_high,
                reasons=reasons + ["Temporary block enforced."],
            )

        if trust_level == TrustLevel.WATCHLIST:
            return AuthenticationDecision(
                supi=trust_record.supi,
                action=AuthenticationAction.STEP_UP,
                confidence=self._confidence_high,
                reasons=reasons + ["Step-up authentication recommended."],
            )

        if own_risk == RiskLevel.HIGH and propagated_level == PropagatedLevel.HIGH:
            return AuthenticationDecision(
                supi=trust_record.supi,
                action=AuthenticationAction.TEMPORARY_BLOCK,
                confidence=self._confidence_high,
                reasons=reasons + ["High self-risk and high propagated risk triggered temporary block."],
            )

        if own_risk == RiskLevel.HIGH:
            return AuthenticationDecision(
                supi=trust_record.supi,
                action=AuthenticationAction.STEP_UP,
                confidence=self._confidence_high,
                reasons=reasons + ["High own-risk requires step-up authentication."],
            )

        if trust_level == TrustLevel.NORMAL and own_risk == RiskLevel.MEDIUM:
            return AuthenticationDecision(
                supi=trust_record.supi,
                action=AuthenticationAction.STEP_UP,
                confidence=self._confidence_medium,
                reasons=reasons + ["Medium own risk prompted step-up authentication."],
            )

        if trust_level == TrustLevel.TRUSTED and own_risk == RiskLevel.LOW and propagated_level == PropagatedLevel.LOW:
            return AuthenticationDecision(
                supi=trust_record.supi,
                action=AuthenticationAction.MONITOR,
                confidence=self._confidence_medium,
                reasons=reasons + ["Trusted subscriber with low own risk and low propagation is monitored."],
            )

        if trust_level == TrustLevel.TRUSTED and own_risk == RiskLevel.LOW and propagated_level == PropagatedLevel.HIGH:
            return AuthenticationDecision(
                supi=trust_record.supi,
                action=AuthenticationAction.STEP_UP,
                confidence=self._confidence_high,
                reasons=reasons + ["High propagated influence requires step-up authentication."],
            )

        if trust_level == TrustLevel.TRUSTED and own_risk == RiskLevel.LOW and propagated_level == PropagatedLevel.NONE:
            return AuthenticationDecision(
                supi=trust_record.supi,
                action=AuthenticationAction.ALLOW,
                confidence=self._confidence_high,
                reasons=reasons + ["Trusted subscriber with no propagated threat allowed."],
            )

        if trust_level == TrustLevel.NORMAL:
            return AuthenticationDecision(
                supi=trust_record.supi,
                action=AuthenticationAction.STEP_UP,
                confidence=self._confidence_medium,
                reasons=reasons + ["Step-up authentication recommended."],
            )

        return AuthenticationDecision(
            supi=trust_record.supi,
            action=AuthenticationAction.MONITOR,
            confidence=self._confidence_medium,
            reasons=reasons + ["Monitoring selected by default policy."],
        )
