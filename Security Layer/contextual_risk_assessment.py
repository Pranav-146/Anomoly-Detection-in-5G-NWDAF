"""Contextual risk assessment for Stage 2.

This module consumes the output of the Stage 1 candidate detector and turns it
into a deterministic, explainable risk assessment. It does not use any machine
learning models and deliberately ignores location-based or network-origin
signals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional, Union


class RiskLevel(str, Enum):
    """Risk levels used by the deterministic Stage 2 assessment."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class CandidateDetection:
    """Structured candidate signal produced after Stage 1 evaluation."""

    supi: str
    rule_detector_result: bool
    reputation_score: Optional[float] = None
    detection_source: Optional[str] = None
    failure_ratio: Optional[float] = None
    timestamp: float = 0.0

    @classmethod
    def from_stage1_output(cls, candidate_output: Mapping[str, Any]) -> "CandidateDetection":
        """Create a candidate descriptor from a Stage 1-style output mapping."""
        tier1 = candidate_output.get("tier1", {}) if isinstance(candidate_output.get("tier1"), Mapping) else {}
        tier2 = candidate_output.get("tier2", {}) if isinstance(candidate_output.get("tier2"), Mapping) else {}

        rule_detector_result = bool(candidate_output.get("rule_detector_result", tier1.get("tier1_candidate", False)))
        reputation_score = candidate_output.get("reputation_score")
        if reputation_score is None:
            reputation_score = tier2.get("score")

        detection_source = candidate_output.get("detection_source")
        if detection_source is None:
            detection_source = candidate_output.get("source")

        failure_ratio = candidate_output.get("failure_ratio")
        if failure_ratio is None:
            failure_ratio = tier1.get("raw_ratio")

        timestamp = candidate_output.get("timestamp", 0.0)
        return cls(
            supi=str(candidate_output.get("supi", "unknown")),
            rule_detector_result=rule_detector_result,
            reputation_score=reputation_score,
            detection_source=str(detection_source) if detection_source is not None else None,
            failure_ratio=failure_ratio,
            timestamp=float(timestamp),
        )


@dataclass
class ContextualRiskAssessmentConfig:
    """Configuration values for deterministic explainable rules."""

    rule_threshold: float = 0.30
    reputation_threshold: float = 0.50
    repeated_failure_threshold: float = 0.30


@dataclass
class RiskAssessment:
    """Deterministic explainable assessment emitted by Stage 2."""

    supi: str
    risk_level: RiskLevel
    risk_score: int
    detection_source: Optional[str]
    timestamp: float
    reasons: list[str] = field(default_factory=list)


class ContextualRiskAssessment:
    """Deterministic Stage 2 assessment over candidate detection output."""

    def __init__(self, cfg: ContextualRiskAssessmentConfig = None) -> None:
        self.cfg = cfg or ContextualRiskAssessmentConfig()

    def assess(self, candidate: Union[CandidateDetection, Mapping[str, Any]]) -> RiskAssessment:
        """Assess a Stage 1 candidate using only deterministic, explainable rules."""
        if isinstance(candidate, CandidateDetection):
            detection = candidate
        else:
            detection = CandidateDetection.from_stage1_output(candidate)

        reasons: list[str] = []
        score = 0

        rule_triggered = bool(detection.rule_detector_result)
        high_reputation = (
            detection.reputation_score is not None and detection.reputation_score >= self.cfg.reputation_threshold
        )

        if rule_triggered:
            reasons.append("Rule threshold exceeded")
            score += 50

        if high_reputation:
            reasons.append("Reputation score exceeded threshold")
            score += 50

        if (
            detection.failure_ratio is not None
            and detection.failure_ratio >= self.cfg.repeated_failure_threshold
            and rule_triggered
            and high_reputation
        ):
            reasons.append("Repeated authentication failures detected")
            score += 20

        score = min(100, score)

        if score >= 100:
            risk_level = RiskLevel.HIGH
        elif score >= 50:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        return RiskAssessment(
            supi=detection.supi,
            risk_level=risk_level,
            risk_score=score,
            detection_source=detection.detection_source,
            timestamp=detection.timestamp,
            reasons=reasons,
        )


def assess_contextual_risk(
    candidate: Union[CandidateDetection, Mapping[str, Any]],
    cfg: ContextualRiskAssessmentConfig = None,
) -> RiskAssessment:
    """Convenience wrapper around ContextualRiskAssessment."""
    assessor = ContextualRiskAssessment(cfg=cfg)
    return assessor.assess(candidate)
