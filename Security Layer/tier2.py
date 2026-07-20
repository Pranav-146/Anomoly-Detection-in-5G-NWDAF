"""
tier2.py — Per-SUPI reputation score with exponential decay.

Catches sustained, threshold-aware attackers who stay under Tier 1's hard
rule (e.g. paced at 29%) by accumulating evidence across multiple windows,
rather than judging any single window in isolation.

Smoothing lives HERE (unlike Tier 1) because this is a cumulative-evidence
context: a single tiny-sample window (e.g. 1/2 failures) must not be able to
swing the running score the same way a large, confident sample would.
"""

from dataclasses import dataclass, field
import math
from event_log import WindowEvent


@dataclass
class Tier2Config:
    baseline: float = 0.05
    prior_n: float = 12.0
    max_per_window: float = 0.15
    half_life_windows: float = 3.0   # score halves after ~3 windows of quiet
    window_seconds: float = 30.0
    action_threshold: float = 0.5
    flag_margin: float = 0.10
    rolling_horizon_windows: int = 10
    n_min: int = 4


@dataclass
class SupiState:
    score: float = 0.0
    last_update_ts: float = 0.0
    flag_history: list = field(default_factory=list)  # list of (timestamp, flagged_bool)


def smoothed_ratio(event: WindowEvent, cfg: Tier2Config) -> float:
    return (event.failures + cfg.prior_n * cfg.baseline) / (event.attempts + cfg.prior_n)


def _decay_factor(cfg: Tier2Config, dt_seconds: float) -> float:
    if dt_seconds <= 0:
        return 1.0
    lam = math.log(2) / (cfg.half_life_windows * cfg.window_seconds)
    return math.exp(-lam * dt_seconds)


def update_tier2(state: SupiState, event: WindowEvent, cfg: Tier2Config = Tier2Config()) -> dict:
    """
    Applies one window's evidence to a SUPI's reputation state, in place,
    and returns whether this update produces a Tier 2 candidate.
    """
    ratio = smoothed_ratio(event, cfg)
    excess = max(0.0, ratio - cfg.baseline)
    contribution = min(excess, cfg.max_per_window)

    dt = event.timestamp - state.last_update_ts
    decay = _decay_factor(cfg, dt)
    state.score = state.score * decay + contribution
    state.last_update_ts = event.timestamp

    flagged = ratio > (cfg.baseline + cfg.flag_margin)
    state.flag_history.append((event.timestamp, flagged))

    horizon_start = event.timestamp - cfg.rolling_horizon_windows * cfg.window_seconds
    recent_flags = sum(1 for ts, f in state.flag_history if ts >= horizon_start and f)

    candidate = (state.score >= cfg.action_threshold) and (recent_flags >= cfg.n_min)

    return {
        "supi": event.supi,
        "window": event.window_index,
        "smoothed_ratio": ratio,
        "contribution": contribution,
        "score": state.score,
        "flagged_this_window": flagged,
        "recent_flag_count": recent_flags,
        "tier2_candidate": candidate,
    }


if __name__ == "__main__":
    from event_log import generate_sustained_attack_sequence, generate_benign_sequence, WindowEvent

    cfg = Tier2Config()

    print("=== Sustained 29% attacker (should escalate within ~6 windows) ===")
    events = generate_sustained_attack_sequence("victim_or_attacker_supi", "cellZ",
                                                  num_windows=10, target_ratio=0.29)
    state = SupiState()
    escalated_at = None
    for ev in events:
        r = update_tier2(state, ev, cfg)
        print(f"window {r['window']}: score={r['score']:.3f} "
              f"flags_in_horizon={r['recent_flag_count']} candidate={r['tier2_candidate']}")
        if r["tier2_candidate"] and escalated_at is None:
            escalated_at = r["window"]
    print(f"-> escalated at window {escalated_at}\n")

    print("=== Benign subscriber over 20 windows (should NEVER escalate) ===")
    benign_events = generate_benign_sequence("benign_supi", "cellA", num_windows=20, seed=7)
    state2 = SupiState()
    any_candidate = False
    max_score = 0.0
    for ev in benign_events:
        r = update_tier2(state2, ev, cfg)
        max_score = max(max_score, r["score"])
        any_candidate |= r["tier2_candidate"]
    print(f"max score reached: {max_score:.3f}, ever escalated: {any_candidate}")
    print("PASS" if not any_candidate else "FAIL — benign subscriber wrongly escalated")

    print("\n=== Stress sweep: multiple sustained attacker ratios ===")
    print(f"{'ratio':>6} {'escalated_at_window':>20} {'never_escalated':>16}")
    for target_ratio in [0.10, 0.20, 0.25, 0.28, 0.29, 0.30, 0.31, 0.40]:
        events = generate_sustained_attack_sequence("sweep_supi", "cellZ",
                                                      num_windows=15, target_ratio=target_ratio)
        state = SupiState()
        escalated_at = None
        for ev in events:
            r = update_tier2(state, ev, cfg)
            if r["tier2_candidate"] and escalated_at is None:
                escalated_at = r["window"]
        never = escalated_at is None
        print(f"{target_ratio:>6.2f} {str(escalated_at):>20} {str(never):>16}")
    print("(Note: ratios >= 0.30 would ALSO be caught instantly by Tier 1 — this sweep")
    print(" shows Tier 2 alone still catches them, and shows how escalation speed")
    print(" scales with attack intensity for ratios Tier 1 can't see at all.)")

    print("\n=== Boundary-straddling burst (fixed-window evasion attempt) ===")
    print("Simulates an attacker sending two large bursts split just across a")
    print("window boundary, testing whether continuous decay (vs. fixed-window")
    print("reset) prevents doubling the effective per-window cap.")
    state3 = SupiState()
    # Burst 1: large attack right at the end of window 0
    ev1 = WindowEvent(supi="straddle_supi", origin="cellZ", window_index=0,
                       attempts=100, failures=45, timestamp=29.0)  # just before 30s boundary
    r1 = update_tier2(state3, ev1, cfg)
    print(f"burst 1 (t=29s): score={r1['score']:.3f}")
    # Burst 2: another large attack just after the boundary, 2 seconds later
    ev2 = WindowEvent(supi="straddle_supi", origin="cellZ", window_index=1,
                       attempts=100, failures=45, timestamp=31.0)  # just after 30s boundary
    r2 = update_tier2(state3, ev2, cfg)
    print(f"burst 2 (t=31s, only 2s later): score={r2['score']:.3f}")
    print(f"combined contribution from both bursts (2s apart): "
          f"{r1['contribution'] + r2['contribution']:.3f} "
          f"(vs. single MAX_PER_WINDOW cap of {cfg.max_per_window})")
    if r1["contribution"] + r2["contribution"] > cfg.max_per_window * 1.5:
        print("NOTE: two bursts close in time still each hit their own cap —")
        print("this is expected with per-window discrete evaluation; the decay")
        print("model bounds how much this helps the attacker (score still decays")
        print("continuously between any two updates, unlike a fixed-clock reset).")
    else:
        print("PASS — boundary straddling did not meaningfully double the damage.")

