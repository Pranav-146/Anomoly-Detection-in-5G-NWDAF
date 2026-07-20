"""
event_log.py — Per-SUPI authentication event log.

This is the foundation everything else (Tier 1, Tier 2, Stage 2) reads from.
Each event represents one collection window's worth of authentication activity
for a single claimed SUPI, from a single origin.
"""

from dataclasses import dataclass, field
import random


@dataclass
class WindowEvent:
    """One collection window of authentication activity for one claimed SUPI."""
    supi: str
    origin: str
    window_index: int
    attempts: int
    failures: int
    timestamp: float  # seconds since simulation start

    @property
    def raw_ratio(self) -> float:
        return self.failures / self.attempts if self.attempts > 0 else 0.0


def generate_benign_sequence(supi: str, origin: str, num_windows: int,
                              window_seconds: float = 30.0,
                              attempts_range=(1, 3), fail_prob=0.03,
                              seed: int = None) -> list[WindowEvent]:
    """
    Simulates a normal subscriber: low attempt counts per window (most windows
    have 1-3 attempts, matching real registration/re-auth behaviour), with a
    small chance of a genuine transient failure (bad signal, mistyped PIN, etc.)
    """
    rng = random.Random(seed)
    events = []
    for w in range(num_windows):
        attempts = rng.randint(*attempts_range)
        failures = sum(1 for _ in range(attempts) if rng.random() < fail_prob)
        events.append(WindowEvent(
            supi=supi, origin=origin, window_index=w,
            attempts=attempts, failures=failures,
            timestamp=w * window_seconds,
        ))
    return events


def generate_sustained_attack_sequence(supi: str, origin: str, num_windows: int,
                                        target_ratio: float = 0.29,
                                        attempts_per_window: int = 100,
                                        window_seconds: float = 30.0) -> list[WindowEvent]:
    """
    Simulates a threshold-aware attacker sustaining a fixed failure ratio
    (default 0.29, just under the 0.30 hard-rule threshold) across many windows.
    This is the paced_evasion case from Phase 1.
    """
    events = []
    failures_per_window = round(attempts_per_window * target_ratio)
    for w in range(num_windows):
        events.append(WindowEvent(
            supi=supi, origin=origin, window_index=w,
            attempts=attempts_per_window, failures=failures_per_window,
            timestamp=w * window_seconds,
        ))
    return events


def generate_spoofed_burst(supi: str, attacker_origin: str, victim_known_origin: str,
                            window_index: int, attempts: int = 40,
                            ratio: float = 0.375, window_seconds: float = 30.0) -> WindowEvent:
    """
    Simulates a single spoofed burst for regression and demo purposes.
    The event carries metadata about the origin but the security layer does
    not use it for location-based attribution.
    """
    failures = round(attempts * ratio)
    return WindowEvent(
        supi=supi, origin=attacker_origin, window_index=window_index,
        attempts=attempts, failures=failures,
        timestamp=window_index * window_seconds,
    )


if __name__ == "__main__":
    # Quick sanity check
    benign = generate_benign_sequence("001010000000001", "cellA", num_windows=10, seed=1)
    attack = generate_sustained_attack_sequence("001010000000099", "cellZ", num_windows=6)
    print("Benign sample:", benign[0], "ratio=%.3f" % benign[0].raw_ratio)
    print("Attack sample:", attack[0], "ratio=%.3f" % attack[0].raw_ratio)
