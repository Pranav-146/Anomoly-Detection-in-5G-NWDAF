import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from contextual_risk_assessment import RiskAssessment, RiskLevel
from trust_risk_repository import TrustLevel, TrustRiskRepository
from collaborative_risk_propagation import CollaborativeRiskPropagation, PropagatedLevel, Relationship, RelationshipType


class CollaborativeRiskPropagationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = TrustRiskRepository()
        self.crp = CollaborativeRiskPropagation(self.repo)

    def _make_record(self, supi: str, trust_level: TrustLevel, risk_score: int) -> None:
        record = self.repo.create_record(supi)
        record.trust_level = trust_level
        record.latest_risk_level = RiskLevel.HIGH if trust_level in {TrustLevel.WATCHLIST, TrustLevel.BLOCKED} else RiskLevel.LOW
        record.latest_risk_score = risk_score
        record.last_updated = 1.0

    def test_single_relationship_propagates_risk(self) -> None:
        self._make_record("imsi-3001", TrustLevel.WATCHLIST, 100)
        self._make_record("imsi-3002", TrustLevel.NORMAL, 0)
        self.crp.add_relationship("imsi-3001", "imsi-3002", RelationshipType.SHARED_DEVICE)

        propagated = self.crp.calculate_propagated_risk("imsi-3002")

        self.assertEqual(propagated.supi, "imsi-3002")
        self.assertEqual(propagated.propagated_level, PropagatedLevel.MEDIUM)
        self.assertEqual(propagated.propagated_score, 50.0)
        self.assertEqual(len(propagated.contributing_neighbors), 1)
        self.assertIn("Shared device", propagated.explanations[0])

    def test_multiple_relationships_aggregate_scores(self) -> None:
        self._make_record("imsi-3010", TrustLevel.BLOCKED, 100)
        self._make_record("imsi-3011", TrustLevel.NORMAL, 0)
        self.crp.add_relationship("imsi-3010", "imsi-3011", RelationshipType.SHARED_DEVICE)
        self.crp.add_relationship("imsi-3010", "imsi-3011", RelationshipType.SHARED_IP)

        propagated = self.crp.calculate_propagated_risk("imsi-3011")

        self.assertEqual(propagated.propagated_score, 90.0)
        self.assertEqual(propagated.propagated_level, PropagatedLevel.HIGH)
        self.assertEqual(len(propagated.contributing_neighbors), 2)

    def test_multiple_contributors_are_counted(self) -> None:
        self._make_record("imsi-3020", TrustLevel.WATCHLIST, 80)
        self._make_record("imsi-3021", TrustLevel.WATCHLIST, 70)
        self._make_record("imsi-3022", TrustLevel.NORMAL, 0)
        self.crp.add_relationship("imsi-3020", "imsi-3022", RelationshipType.SHARED_SLICE)
        self.crp.add_relationship("imsi-3021", "imsi-3022", RelationshipType.SHARED_AMF)

        propagated = self.crp.calculate_propagated_risk("imsi-3022")

        self.assertEqual(len(propagated.contributing_neighbors), 2)
        self.assertIn("Two contributing neighbors", propagated.explanations[-1])

    def test_blocked_propagation_is_allowed(self) -> None:
        self._make_record("imsi-3030", TrustLevel.BLOCKED, 90)
        self._make_record("imsi-3031", TrustLevel.NORMAL, 0)
        self.crp.add_relationship("imsi-3030", "imsi-3031", RelationshipType.CUSTOM, weight=0.7)

        propagated = self.crp.calculate_propagated_risk("imsi-3031")

        self.assertEqual(propagated.propagated_score, 63.0)
        self.assertEqual(propagated.propagated_level, PropagatedLevel.MEDIUM)

    def test_watchlist_propagation_is_allowed(self) -> None:
        self._make_record("imsi-3040", TrustLevel.WATCHLIST, 60)
        self._make_record("imsi-3041", TrustLevel.NORMAL, 0)
        self.crp.add_relationship("imsi-3040", "imsi-3041", RelationshipType.SHARED_IP)

        propagated = self.crp.calculate_propagated_risk("imsi-3041")

        self.assertEqual(propagated.propagated_score, 24.0)
        self.assertEqual(propagated.propagated_level, PropagatedLevel.LOW)

    def test_trusted_subscriber_produces_no_propagation(self) -> None:
        self._make_record("imsi-3050", TrustLevel.TRUSTED, 100)
        self._make_record("imsi-3051", TrustLevel.NORMAL, 0)
        self.crp.add_relationship("imsi-3050", "imsi-3051", RelationshipType.SHARED_DEVICE)

        propagated = self.crp.calculate_propagated_risk("imsi-3051")

        self.assertEqual(propagated.propagated_score, 0.0)
        self.assertEqual(propagated.propagated_level, PropagatedLevel.NONE)
        self.assertEqual(propagated.contributing_neighbors, [])

    def test_normal_subscriber_produces_no_propagation(self) -> None:
        self._make_record("imsi-3060", TrustLevel.NORMAL, 100)
        self._make_record("imsi-3061", TrustLevel.NORMAL, 0)
        self.crp.add_relationship("imsi-3060", "imsi-3061", RelationshipType.SHARED_DEVICE)

        propagated = self.crp.calculate_propagated_risk("imsi-3061")

        self.assertEqual(propagated.propagated_score, 0.0)
        self.assertEqual(propagated.propagated_level, PropagatedLevel.NONE)

    def test_relationship_removal_works(self) -> None:
        self._make_record("imsi-3070", TrustLevel.WATCHLIST, 80)
        self._make_record("imsi-3071", TrustLevel.NORMAL, 0)
        self.crp.add_relationship("imsi-3070", "imsi-3071", RelationshipType.SHARED_DEVICE)
        self.crp.remove_relationship("imsi-3070", "imsi-3071", RelationshipType.SHARED_DEVICE)

        propagated = self.crp.calculate_propagated_risk("imsi-3071")

        self.assertEqual(propagated.propagated_score, 0.0)
        self.assertEqual(propagated.contributing_neighbors, [])

    def test_empty_repository_returns_zero_propagation(self) -> None:
        propagated = self.crp.calculate_propagated_risk("imsi-3080")

        self.assertEqual(propagated.propagated_score, 0.0)
        self.assertEqual(propagated.propagated_level, PropagatedLevel.NONE)
        self.assertEqual(propagated.explanations, ["No contributing neighbors"])


if __name__ == "__main__":
    unittest.main()
