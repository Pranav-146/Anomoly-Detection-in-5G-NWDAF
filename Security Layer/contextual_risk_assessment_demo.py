"""Small demo showing a few Stage 1 candidates flowing into Stage 2."""

from contextual_risk_assessment import (
    CandidateDetection,
    ContextualRiskAssessmentConfig,
    assess_contextual_risk,
)


if __name__ == "__main__":
    cfg = ContextualRiskAssessmentConfig()
    candidates = [
        CandidateDetection(
            supi="imsi-1001",
            rule_detector_result=False,
            reputation_score=0.20,
            detection_source="IF",
            failure_ratio=0.10,
            timestamp=100.0,
        ),
        CandidateDetection(
            supi="imsi-1002",
            rule_detector_result=True,
            reputation_score=0.20,
            detection_source="RULE",
            failure_ratio=0.35,
            timestamp=110.0,
        ),
        CandidateDetection(
            supi="imsi-1003",
            rule_detector_result=False,
            reputation_score=0.60,
            detection_source="IF",
            failure_ratio=0.20,
            timestamp=120.0,
        ),
        CandidateDetection(
            supi="imsi-1004",
            rule_detector_result=True,
            reputation_score=0.70,
            detection_source="BOTH",
            failure_ratio=0.40,
            timestamp=130.0,
        ),
    ]

    for candidate in candidates:
        assessment = assess_contextual_risk(candidate, cfg=cfg)
        print(f"SUPI={assessment.supi} risk={assessment.risk_level.value} score={assessment.risk_score} source={assessment.detection_source}")
        for explanation in assessment.explanations:
            print(f"  - {explanation}")
        print()
