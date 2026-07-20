"""Post a synthetic policy decision event to the local security-gate service."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request


def main() -> int:
    parser = argparse.ArgumentParser(description="Inject a security policy decision event")
    parser.add_argument("--supi", required=True)
    parser.add_argument("--exception-id", required=True)
    parser.add_argument("--tier", choices=["re_challenge", "throttle", "escalate"], required=True)
    parser.add_argument("--base-url", default=os.environ.get("SECURITY_GATE_URL", "http://127.0.0.1:8765"))
    parser.add_argument("--token", default=os.environ.get("SECURITY_GATE_TOKEN", "dev-token"))
    args = parser.parse_args()

    payload = {
        "supi": args.supi,
        "exception_id": args.exception_id,
        "tier": args.tier,
        "failure_ratio": 0.29,
        "baseline_ratio": 0.05,
        "excess_ratio": 0.24,
        "reputation_score": 0.71,
    }
    req = urllib.request.Request(
        f"{args.base_url}/api/security/policy-decision",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Policy-Token": args.token},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as response:
            body = response.read().decode("utf-8")
            print(body)
    except Exception as exc:  # pragma: no cover - CLI wiring
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
