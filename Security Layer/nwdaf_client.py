"""
nwdaf_client.py — Real NWDAF data source for the security layer.

Talks to the ACTUAL sa_core REST API (core/webservice/app/routes_nwdaf_analytics.go),
not the NWDAF-computed verdict. We deliberately read from:

    GET /api/nwdaf/export?analytics_id=ABNORMAL_BEHAVIOUR&imsi=<supi>

...because this returns the raw persisted pm_counters (AUTH.Att / AUTH.Fail)
per collection window, which Tier 2 needs to see even when NWDAF's own
verdict would say "not detected" (sub-threshold). NWDAF's own precomputed
verdict (GET /api/nwdaf/analytics/ABNORMAL_BEHAVIOUR) is intentionally NOT
used as our detection input — this security layer is meant to catch what
NWDAF's own rule misses, so feeding it NWDAF's own verdict would be circular.

SCHEMA GAP (documented, not silently worked around):
sa_core's `nwdaf_data_points` table has no origin/cell column
(source_nf/analytics_id/imsi/dnn/sst/data_json/collected_at only — confirmed
by reading core/nf/nwdaf/api.go). Real events therefore have no ground-truth
origin. We do NOT fabricate one. Two supported behaviours, controlled by
`origin_field`:
  - origin_field=None (default): origin is always set to None on real events.
    Stage 2 will correctly fall into its cold-start / insufficient-evidence
    path for every real event until the schema gap is closed properly
    (Go migration owned by the team, not faked here).
  - origin_field="<key>": if the tester/injector chose to smuggle an origin
    string into the schemaless `data_json` blob under that key (e.g. as
    part of the `experiment` metadata dict), we'll read it back. This is a
    same-day workaround for carrying contextual metadata into the demo flow
    without a Go schema change; it must be documented as such in the report,
    not presented as a production mechanism.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from event_log import WindowEvent


class NWDAFUnavailable(Exception):
    """Raised when sa_core's NWDAF API cannot be reached at all."""


@dataclass
class NWDAFClientConfig:
    base_url: str = "http://localhost:5000"
    analytics_id: str = "ABNORMAL_BEHAVIOUR"
    timeout_seconds: float = 5.0
    # See module docstring. Set to e.g. "origin" if your injector writes
    # data_json = {"pm_counters": {...}, "experiment": {"origin": "cellA", ...}}
    origin_field: str | None = None


def _request_json(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _post_json(url: str, body: dict, timeout: float) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _row_to_event(row: dict, window_index: int, origin_field: str | None) -> WindowEvent | None:
    """
    Converts one raw /api/nwdaf/export row into a WindowEvent.
    Returns None if the row doesn't carry usable pm_counters (malformed /
    partial data should never crash the live engine).
    """
    imsi = row.get("imsi") or row.get("IMSI")
    data_json_raw = row.get("data_json") or row.get("DataJSON")
    collected_at = row.get("collected_at") or row.get("CollectedAt") or 0.0
    if not imsi or not data_json_raw:
        return None

    try:
        payload = json.loads(data_json_raw) if isinstance(data_json_raw, str) else data_json_raw
    except (json.JSONDecodeError, TypeError):
        return None

    pm = payload.get("pm_counters") or {}
    attempts = pm.get("AUTH.Att")
    failures = pm.get("AUTH.Fail")
    if attempts is None or failures is None:
        return None

    origin = None
    if origin_field:
        experiment = payload.get("experiment") or {}
        origin = experiment.get(origin_field) or payload.get(origin_field)

    return WindowEvent(
        supi=str(imsi),
        origin=origin,  # None unless origin_field workaround is configured — see module docstring
        window_index=window_index,
        attempts=int(attempts),
        failures=int(failures),
        timestamp=float(collected_at),
    )


def fetch_events(supi: str, cfg: NWDAFClientConfig = None, limit: int = 1000,
                  since_unix: float = 0.0) -> list[WindowEvent]:
    """
    Pulls all persisted raw data points for one SUPI from the real sa_core
    NWDAF export endpoint and converts them into WindowEvents, in
    chronological order, ready to feed one-by-one into
    SecurityLayerEngine.process_event().

    Fails gracefully: raises NWDAFUnavailable (caller decides how to handle
    a down core — e.g. skip this poll cycle) rather than letting a raw
    connection error propagate into the live engine loop.
    """
    cfg = cfg or NWDAFClientConfig()
    qs = urllib.parse.urlencode({
        "analytics_id": cfg.analytics_id,
        "imsi": supi,
        "limit": limit,
        "since_unix": since_unix,
    })
    url = f"{cfg.base_url.rstrip('/')}/api/nwdaf/export?{qs}"

    try:
        payload = _request_json(url, cfg.timeout_seconds)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ConnectionError) as exc:
        raise NWDAFUnavailable(f"sa_core NWDAF export unreachable at {cfg.base_url}: {exc}") from exc

    rows = payload.get("rows") or []
    rows.sort(key=lambda r: r.get("collected_at") or r.get("CollectedAt") or 0.0)

    events = []
    for idx, row in enumerate(rows):
        ev = _row_to_event(row, window_index=idx, origin_field=cfg.origin_field)
        if ev is not None:
            events.append(ev)
    return events


def post_test_datapoint(supi: str, attempts: int, failures: int, collected_at: float,
                         cfg: NWDAFClientConfig = None, origin: str | None = None,
                         extra_meta: dict | None = None) -> None:
    """
    Convenience helper for INJECTING a data point the same way
    tester/tools/nwdaf_threshold_sweep.py does (POST /api/nwdaf/data).
    Not used by the live read path — provided so the security layer's own
    test/demo scripts can drive real sa_core data without depending on the
    separate tester tool. If `origin` is given, it's smuggled into the
    schemaless data_json.experiment blob under cfg.origin_field so
    fetch_events() can read it back (same-day workaround; see module docstring).
    """
    cfg = cfg or NWDAFClientConfig()
    experiment = dict(extra_meta or {})
    if origin is not None and cfg.origin_field:
        experiment[cfg.origin_field] = origin

    data_json = {
        "pm_counters": {"AUTH.Att": attempts, "AUTH.Fail": failures, "AUTH.FailMAC": 0},
        "experiment": experiment,
    }
    body = {
        "source_nf": "AMF",
        "analytics_id": cfg.analytics_id,
        "imsi": supi,
        "data_json": json.dumps(data_json, separators=(",", ":")),
        "collected_at": collected_at,
    }
    url = f"{cfg.base_url.rstrip('/')}/api/nwdaf/data"
    try:
        _post_json(url, body, cfg.timeout_seconds)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ConnectionError) as exc:
        raise NWDAFUnavailable(f"sa_core NWDAF ingest unreachable at {cfg.base_url}: {exc}") from exc


if __name__ == "__main__":
    # Manual smoke test against whatever's at cfg.base_url. Fails gracefully
    # (prints a clear message, doesn't stack-trace) if nothing is running.
    cfg = NWDAFClientConfig()
    try:
        events = fetch_events("001010000000001", cfg)
        print(f"Fetched {len(events)} real events for test SUPI.")
        for ev in events[:5]:
            print(f"  window={ev.window_index} attempts={ev.attempts} "
                  f"failures={ev.failures} ratio={ev.raw_ratio:.3f} origin={ev.origin}")
    except NWDAFUnavailable as exc:
        print(f"[nwdaf_client] sa_core not reachable — this is expected if the "
              f"core isn't running right now: {exc}")
