"""HMAC authenticity is insufficient for freshness and idempotent business effects."""
import base64
import hmac
import json

KEY = b"PUBLIC-WEBHOOK-LAB-KEY"
NOW = 1800000000
BODY = b'{"event":"demo.credit","amount":1}'


def signature(message_id, timestamp, body):
    signed = f"{message_id}.{timestamp}.".encode() + body
    return "v1," + base64.b64encode(hmac.digest(KEY, signed, "sha256")).decode()


class Consumer:
    def __init__(self, *, fixed):
        self.fixed = fixed
        self.seen = set()
        self.effects = 0

    def receive(self, message_id, timestamp, body, supplied_signature, now=NOW):
        if not isinstance(timestamp, int) or isinstance(timestamp, bool):
            return False
        if not hmac.compare_digest(signature(message_id, timestamp, body), supplied_signature):
            return False
        if self.fixed and (abs(now - timestamp) > 300 or message_id in self.seen):
            return False
        # Atomicity is assumed by this single-threaded fixture. Production needs a transaction.
        self.seen.add(message_id)
        self.effects += 1
        return True


def demo():
    sig = signature("message-1", NOW, BODY)
    before, after = Consumer(fixed=False), Consumer(fixed=True)
    first_before = before.receive("message-1", NOW, BODY, sig)
    first_after = after.receive("message-1", NOW, BODY, sig)
    duplicate_before = before.receive("message-1", NOW, BODY, sig)
    duplicate_after = after.receive("message-1", NOW, BODY, sig)
    return {"attack": "Replay the same correctly signed event within the freshness window",
            "vulnerable_accepts": duplicate_before, "fixed_accepts": duplicate_after,
            "legitimate_accepts": first_before and first_after,
            "vulnerable_business_effects": before.effects, "fixed_business_effects": after.effects,
            "boundary": "In-memory receiver and synthetic event; no webhook is sent"}


if __name__ == "__main__":
    print(json.dumps(demo(), indent=2))
