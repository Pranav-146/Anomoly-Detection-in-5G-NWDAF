"""Demonstrate the complete adaptive authentication pipeline."""

from adaptive_authentication_pipeline import AdaptiveAuthenticationPipeline


if __name__ == "__main__":
    pipeline = AdaptiveAuthenticationPipeline()

    events = [
        {"supi": "imsi-10001", "rule_detector_result": False, "reputation_score": 0.20, "detection_source": "RULE", "failure_ratio": 0.10, "timestamp": 100.0},
        {"supi": "imsi-10002", "rule_detector_result": False, "reputation_score": 0.40, "detection_source": "RULE", "failure_ratio": 0.10, "timestamp": 101.0},
        {"supi": "imsi-10003", "rule_detector_result": True, "reputation_score": 0.20, "detection_source": "RULE", "failure_ratio": 0.20, "timestamp": 102.0},
        {"supi": "imsi-10004", "rule_detector_result": True, "reputation_score": 0.80, "detection_source": "RULE", "failure_ratio": 0.40, "timestamp": 103.0},
    ]

    for event in events:
        result = pipeline.process(event)
        print(f"Subscriber: {event['supi']}")
        print(f"Detection Result: {result.detection_result}")
        print(f"Risk Level: {result.contextual_risk.risk_level.value}")
        print(f"Trust Level: {result.trust_record.trust_level.value}")
        print(f"Propagated Risk: {result.propagated_risk.propagated_level.value}")
        print(f"Policy Decision: {result.authentication_decision.action.value}")
        print(f"Execution Method: {result.authentication_result.authentication_method.value}")
        print(f"Final Status: {result.authentication_result.status.value}")
        print("Pipeline Log:")
        for entry in result.pipeline_log:
            print(f"- {entry}")
        print()
