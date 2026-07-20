"""
tier1.py — Hard-rule detector on the raw failure ratio.

Matches the original 3GPP-style ABNORMAL_BEHAVIOUR rule (default 30%) EXACTLY —
no smoothing here, because smoothing (needed elsewhere for small-sample
statistical noise) would shift this rule's boundary away from the literal
published spec number, which defeats the point of Tier 1 being a faithful
hard-rule replica.

Instead, tiny/meaningless samples (e.g. 1 failure / 2 attempts) are handled
by a minimum-attempt gate: a window with too few attempts to be statistically
meaningful is simply not evaluated by this rule at all.

This tier is UNCONDITIONAL: nothing else (origin, attribution) is allowed to
suppress it once it fires on a window with enough attempts. It only ever
produces a *candidate* — Stage 2 decides who gets enforced.
"""

from dataclasses import dataclass
from event_log import WindowEvent


@dataclass
class Tier1Config:
    threshold: float = 0.30      # configurable; default matches 3GPP rule exactly
    min_attempts: int = 5        # windows with fewer attempts are not evaluated


def tier1_check(event: WindowEvent, cfg: Tier1Config = Tier1Config()) -> dict:
    """
    Returns a dict with the raw ratio and whether this window is a
    Tier 1 candidate (unconditional hard-rule breach).
    """
    if event.attempts < cfg.min_attempts:
        return {
            "supi": event.supi,
            "window": event.window_index,
            "raw_ratio": event.raw_ratio,
            "tier1_candidate": False,
            "reason": f"below min_attempts ({event.attempts} < {cfg.min_attempts}), not evaluated",
        }
    ratio = event.raw_ratio
    return {
        "supi": event.supi,
        "window": event.window_index,
        "raw_ratio": ratio,
        "tier1_candidate": ratio >= cfg.threshold,
        "reason": None,
    }


if __name__ == "__main__":
    # Validation: known ratios should flag exactly where expected, matching
    # the literal 3GPP 30% boundary with no distortion.
    cfg = Tier1Config()
    test_cases = [
        # (attempts, failures, expected_candidate)
        (2, 1, False),       # typo case: too few attempts, gated out regardless of ratio
        (100, 0, False),     # clean
        (100, 15, False),    # 15% - well under
        (100, 29, False),    # 29% - just under hard rule
        (100, 30, True),     # exactly at hard rule - must fire
        (100, 45, True),     # well above
    ]
    print(f"{'attempts':>8} {'failures':>8} {'raw':>6} {'flagged':>8} {'expected':>8} {'OK'}")
    all_ok = True
    for attempts, failures, expected in test_cases:
        ev = WindowEvent(supi="test", origin="cellA", window_index=0,
                          attempts=attempts, failures=failures, timestamp=0.0)
        result = tier1_check(ev, cfg)
        ok = result["tier1_candidate"] == expected
        all_ok &= ok
        print(f"{attempts:>8} {failures:>8} {result['raw_ratio']:>6.2f} "
              f"{str(result['tier1_candidate']):>8} {str(expected):>8} {'PASS' if ok else 'FAIL'}")
    print("\nALL PASS" if all_ok else "\nSOME FAILED")
