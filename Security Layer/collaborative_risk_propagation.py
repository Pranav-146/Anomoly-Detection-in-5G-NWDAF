"""Deterministic collaborative risk propagation for related subscribers."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from trust_risk_repository import TrustRiskRepository, TrustLevel


class RelationshipType(str, Enum):
    """Supported relationship types for collaborative risk propagation."""

    SHARED_DEVICE = "SHARED_DEVICE"
    SHARED_IP = "SHARED_IP"
    SHARED_SLICE = "SHARED_SLICE"
    SHARED_AMF = "SHARED_AMF"
    CUSTOM = "CUSTOM"


class PropagatedLevel(str, Enum):
    """Risk levels for propagated influence."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class Relationship:
    """A lightweight relationship between two subscribers."""

    source_supi: str
    target_supi: str
    relationship_type: RelationshipType
    weight: float
    timestamp: float


@dataclass
class PropagatedRisk:
    """The propagated trust influence for a subscriber."""

    supi: str
    propagated_score: float
    propagated_level: PropagatedLevel
    contributing_neighbors: list[str]
    explanations: list[str]


class CollaborativeRiskPropagation:
    """Read-only propagation engine over trust records and relationships."""

    DEFAULT_SHARED_DEVICE_WEIGHT = 0.50
    DEFAULT_SHARED_IP_WEIGHT = 0.40
    DEFAULT_SHARED_SLICE_WEIGHT = 0.30
    DEFAULT_SHARED_AMF_WEIGHT = 0.20
    HIGH_PROPAGATION_THRESHOLD = 75.0

    def __init__(self, repository: TrustRiskRepository) -> None:
        self.repository = repository
        self._relationships: list[Relationship] = []

    def add_relationship(
        self,
        source_supi: str,
        target_supi: str,
        relationship_type: RelationshipType,
        weight: Optional[float] = None,
        timestamp: Optional[float] = None,
    ) -> Relationship:
        """Create and store a relationship between two subscribers."""
        relationship = Relationship(
            source_supi=source_supi,
            target_supi=target_supi,
            relationship_type=relationship_type,
            weight=self._default_weight(relationship_type) if weight is None else weight,
            timestamp=timestamp if timestamp is not None else 0.0,
        )
        self._relationships.append(relationship)
        return relationship

    def remove_relationship(self, source_supi: str, target_supi: str, relationship_type: RelationshipType) -> None:
        """Remove the first matching relationship."""
        self._relationships = [
            item
            for item in self._relationships
            if not (
                item.source_supi == source_supi
                and item.target_supi == target_supi
                and item.relationship_type == relationship_type
            )
        ]

    def get_neighbors(self, supi: str) -> list[Relationship]:
        """Return relationships that target the given subscriber."""
        return [relationship for relationship in self._relationships if relationship.target_supi == supi]

    def calculate_propagated_risk(self, supi: str) -> PropagatedRisk:
        """Compute the propagated risk for a subscriber from neighboring records."""
        score = 0.0
        contributing_neighbors: list[str] = []
        explanations: list[str] = []

        for relationship in self.get_neighbors(supi):
            source_record = self.repository.get_record(relationship.source_supi)
            if source_record is None:
                continue

            if source_record.trust_level not in {TrustLevel.WATCHLIST, TrustLevel.BLOCKED}:
                continue

            if source_record.latest_risk_score is None:
                continue

            contribution = relationship.weight * float(source_record.latest_risk_score)
            score += contribution
            contributing_neighbors.append(relationship.source_supi)
            explanations.append(
                self._relationship_explanation(relationship.relationship_type, relationship.source_supi)
            )

        normalized_score = min(100.0, score)
        propagated_level = self._classify_propagated_score(normalized_score)

        if not contributing_neighbors:
            return PropagatedRisk(
                supi=supi,
                propagated_score=0.0,
                propagated_level=PropagatedLevel.NONE,
                contributing_neighbors=[],
                explanations=["No contributing neighbors"],
            )

        if len(contributing_neighbors) >= 2:
            explanations.append("Two contributing neighbors")
        else:
            explanations.append("One contributing neighbor")

        return PropagatedRisk(
            supi=supi,
            propagated_score=round(normalized_score, 2),
            propagated_level=propagated_level,
            contributing_neighbors=contributing_neighbors,
            explanations=explanations,
        )

    def calculate_all(self) -> list[PropagatedRisk]:
        """Calculate propagated risk for all subscribers present in the repository."""
        return [self.calculate_propagated_risk(supi) for supi in sorted(self.repository._records)]

    def clear(self) -> None:
        """Remove all stored relationships."""
        self._relationships.clear()

    def _default_weight(self, relationship_type: RelationshipType) -> float:
        weights = {
            RelationshipType.SHARED_DEVICE: self.DEFAULT_SHARED_DEVICE_WEIGHT,
            RelationshipType.SHARED_IP: self.DEFAULT_SHARED_IP_WEIGHT,
            RelationshipType.SHARED_SLICE: self.DEFAULT_SHARED_SLICE_WEIGHT,
            RelationshipType.SHARED_AMF: self.DEFAULT_SHARED_AMF_WEIGHT,
            RelationshipType.CUSTOM: 1.0,
        }
        return weights[relationship_type]

    def _classify_propagated_score(self, score: float) -> PropagatedLevel:
        if score <= 0:
            return PropagatedLevel.NONE
        if score <= 49:
            return PropagatedLevel.LOW
        if score <= 74:
            return PropagatedLevel.MEDIUM
        return PropagatedLevel.HIGH

    def _relationship_explanation(self, relationship_type: RelationshipType, source_supi: str) -> str:
        labels = {
            RelationshipType.SHARED_DEVICE: "Shared device",
            RelationshipType.SHARED_IP: "Shared IP",
            RelationshipType.SHARED_SLICE: "Shared slice",
            RelationshipType.SHARED_AMF: "Shared AMF",
            RelationshipType.CUSTOM: "Custom relationship",
        }
        return f"{labels[relationship_type]} with {source_supi}"
