"""End-to-end adaptive authentication pipeline orchestrating existing modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from adaptive_authentication_policy_engine import AdaptiveAuthenticationPolicyEngine, AuthenticationDecision
from adaptive_hmac_authentication import AdaptiveHMACAuthentication, AuthenticationResult
from collaborative_risk_propagation import CollaborativeRiskPropagation, PropagatedRisk
from contextual_risk_assessment import CandidateDetection, ContextualRiskAssessment, RiskAssessment
from trust_risk_repository import TrustRecord, TrustRiskRepository


@dataclass
class PipelineResult:
    """Complete processing trace for a single authentication request."""

    authentication_event: Any
    detection_result: Any
    contextual_risk: Optional[RiskAssessment] = None
    trust_record: Optional[TrustRecord] = None
    propagated_risk: Optional[PropagatedRisk] = None
    authentication_decision: Optional[AuthenticationDecision] = None
    authentication_result: Optional[AuthenticationResult] = None
    pipeline_log: list[str] = field(default_factory=list)


class AdaptiveAuthenticationPipeline:
    """Orchestrates the complete authentication workflow using existing modules."""

    def __init__(self) -> None:
        self.stage1_detector = None
        self.detection_adapter = None
        self.contextual_assessor = ContextualRiskAssessment()
        self.trust_repository = TrustRiskRepository()
        self.collaborative_propagation = CollaborativeRiskPropagation(self.trust_repository)
        self.policy_engine = AdaptiveAuthenticationPolicyEngine()
        self.auth_executor = AdaptiveHMACAuthentication()

    def process(self, authentication_event: Any) -> PipelineResult:
        """Run the complete authentication workflow for a single event."""
        if authentication_event is None:
            raise ValueError("authentication_event is required")

        if not isinstance(authentication_event, dict):
            raise TypeError("authentication_event must be a mapping")

        if "supi" not in authentication_event:
            raise ValueError("authentication_event must include a supi")

        pipeline_log: list[str] = []
        pipeline_log.append("Authentication request received.")

        stage1_result = self._run_stage1_detection(authentication_event)
        pipeline_log.append("Stage 1 detection completed.")

        adapted_result = self._run_detection_adapter(stage1_result)
        pipeline_log.append("Detection adapter completed.")

        contextual_risk = self._run_contextual_assessment(adapted_result)
        pipeline_log.append("Contextual risk assessed.")

        trust_record = self._update_trust_repository(contextual_risk)
        pipeline_log.append("Trust repository updated.")

        propagated_risk = self._run_collaborative_propagation(trust_record)
        pipeline_log.append("Collaborative propagation calculated.")

        decision = self._generate_policy_decision(trust_record, propagated_risk)
        pipeline_log.append("Policy engine selected an authentication action.")

        authentication_result = self._execute_authentication(decision)
        pipeline_log.append("Adaptive HMAC executed.")
        pipeline_log.append("Authentication completed.")

        return PipelineResult(
            authentication_event=authentication_event,
            detection_result=stage1_result,
            contextual_risk=contextual_risk,
            trust_record=trust_record,
            propagated_risk=propagated_risk,
            authentication_decision=decision,
            authentication_result=authentication_result,
            pipeline_log=pipeline_log,
        )

    def _run_stage1_detection(self, authentication_event: dict[str, Any]) -> Any:
        if self.stage1_detector is None:
            return authentication_event
        return self.stage1_detector(authentication_event)

    def _run_detection_adapter(self, stage1_result: Any) -> Any:
        if self.detection_adapter is None:
            return stage1_result
        return self.detection_adapter(stage1_result)

    def _run_contextual_assessment(self, adapted_result: Any) -> RiskAssessment:
        if isinstance(adapted_result, RiskAssessment):
            return adapted_result
        return self.contextual_assessor.assess(adapted_result)

    def _update_trust_repository(self, contextual_risk: RiskAssessment) -> TrustRecord:
        return self.trust_repository.update_from_assessment(contextual_risk)

    def _run_collaborative_propagation(self, trust_record: TrustRecord) -> PropagatedRisk:
        return self.collaborative_propagation.calculate_propagated_risk(trust_record.supi)

    def _generate_policy_decision(self, trust_record: TrustRecord, propagated_risk: PropagatedRisk) -> AuthenticationDecision:
        return self.policy_engine.evaluate(trust_record, propagated_risk)

    def _execute_authentication(self, decision: AuthenticationDecision) -> AuthenticationResult:
        return self.auth_executor.execute(decision)
