# 09 — Authentic does not mean new

**Scope:** a single-process webhook-consumer fixture with a synthetic credit event. **Entry:** the same signed message submitted twice within the accepted time window. **Precondition:** the receiver verifies authenticity but does not deduplicate business effects.

```bash
python3 lab_webhook_replay.py
```

The vulnerable receiver applies two effects; the fixed receiver applies one. The second delivery has a valid HMAC, so signature checking alone cannot distinguish a replay. The first legitimate delivery remains accepted.

**Impact demonstrated:** repeated processing of an authentic event. The counter is synthetic; no payment, external webhook or account balance is touched.

**Fix:** bind message ID, timestamp and raw body into the signature; enforce a bounded past/future timestamp window; track processed IDs. In production the deduplication decision and business operation need an atomic transaction or equivalent idempotency design.

**Retest:** stale and future events, changed body, changed ID and invalid signatures fail. A rejected signature does not reserve the ID and block a later valid event.

**Limit:** the in-memory set has no persistence, concurrency control, expiry policy or key rotation. Duplicate delivery is also normal in reliable webhook systems; a production endpoint may acknowledge a duplicate successfully while suppressing its effect, unlike this boolean fixture.

**Reference:** [Standard Webhooks specification](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md).
