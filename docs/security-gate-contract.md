# Security Gate Handoff Contract

## Identifier choice
- The decision gate and policy handler use the `supi` field everywhere. This keeps the handoff aligned with the subscriber identifier used in the existing telemetry and event logs.

## Allowed tiers
- `re_challenge`
- `throttle`
- `escalate`

## Exception idempotency
- Duplicate `exception_id` values are treated as idempotent for the policy handler: the second event is rejected with a duplicate error and no new enforcement action is produced.

## Authentication between gate and policy endpoint
- The MVP uses a shared secret bearer token via the `X-Policy-Token` header. The service rejects requests without a matching token.

## Subscriber attribution ownership
- The NWDAF collector path records the raw analytics window and the claimed SUPI. The decision gate owns subscriber attribution and the policy handler consumes the gate's verdict without re-attributing the event.

## Payload contract
```json
{
  "supi": "imsi-001010123456789",
  "exception_id": "campaign-00042",
  "tier": "re_challenge",
  "gate_timestamp_unix_ns": 1783056007000000000,
  "failure_ratio": 0.29,
  "baseline_ratio": 0.05,
  "excess_ratio": 0.24,
  "reputation_score": 0.71
}
```
