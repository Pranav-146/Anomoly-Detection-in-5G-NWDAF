"""
stepup_auth.py — Adaptive step-up re-authentication.

When a SUPI/origin appears in the TRR, instead of an outright reject, the
network issues a cryptographic nonce challenge. The subscriber proves
legitimacy via HMAC-SHA256 using a shared secret (provisioned during initial
subscription, analogous to existing AKA key material) — NOT a knowledge-based
question, which NIST SP 800-63B no longer recommends as an authentication
factor.
"""

import hmac
import hashlib
import os
import time


def issue_challenge() -> bytes:
    """AMF generates a random nonce for this challenge."""
    return os.urandom(16)


def compute_response(shared_secret: bytes, nonce: bytes) -> str:
    """Subscriber side: HMAC-SHA256(shared_secret, nonce)."""
    return hmac.new(shared_secret, nonce, hashlib.sha256).hexdigest()


def verify_response(shared_secret: bytes, nonce: bytes, response: str) -> bool:
    """AMF side: recompute and compare using constant-time comparison."""
    expected = compute_response(shared_secret, nonce)
    return hmac.compare_digest(expected, response)


def step_up_flow(trr, target_id: str, claimed_secret: bytes, real_secret: bytes,
                  now: float) -> dict:
    """
    Full step-up flow: if target_id is blocked in the TRR, issue a challenge
    and verify. Clears the TRR entry on success, leaves it in place (until
    expiry) on failure.
    """
    if not trr.is_blocked(target_id, now):
        return {"target_id": target_id, "challenge_needed": False, "result": "allowed"}

    nonce = issue_challenge()
    response = compute_response(claimed_secret, nonce)  # what the requester sends
    ok = verify_response(real_secret, nonce, response)  # what the network checks against

    if ok:
        trr.clear_on_verification(target_id)
        return {"target_id": target_id, "challenge_needed": True, "result": "verified_cleared"}
    else:
        return {"target_id": target_id, "challenge_needed": True, "result": "verification_failed_still_blocked"}


if __name__ == "__main__":
    from trr import TrustRiskRepository

    print("=== Legitimate subscriber proves identity, gets unblocked ===")
    trr = TrustRiskRepository(default_expiry_seconds=60.0)
    trr.add_risk("victim_supi", "supi", "high", "tier2", now=0.0)
    real_secret = b"subscriber_shared_secret_001"
    result = step_up_flow(trr, "victim_supi", claimed_secret=real_secret,
                           real_secret=real_secret, now=5.0)
    print(result)
    assert result["result"] == "verified_cleared"
    assert trr.is_blocked("victim_supi", now=6.0) == False
    print("PASS\n")

    print("=== Attacker without the real secret fails the challenge ===")
    trr2 = TrustRiskRepository(default_expiry_seconds=60.0)
    trr2.add_risk("some_origin", "origin", "high", "tier1", now=0.0)
    real_secret2 = b"real_subscriber_secret"
    attacker_guess = b"wrong_guessed_secret"
    result2 = step_up_flow(trr2, "some_origin", claimed_secret=attacker_guess,
                            real_secret=real_secret2, now=5.0)
    print(result2)
    assert result2["result"] == "verification_failed_still_blocked"
    assert trr2.is_blocked("some_origin", now=6.0) == True
    print("PASS\n")

    print("=== Nonce is fresh every time (replay resistance check) ===")
    n1, n2 = issue_challenge(), issue_challenge()
    print(f"nonce1 == nonce2: {n1 == n2}")
    assert n1 != n2
    print("PASS")
