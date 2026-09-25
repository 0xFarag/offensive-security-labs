"""Authorization-code redemption state machine; no OAuth provider is contacted."""
import base64
import hashlib
import hmac
import json

NOW = 1800000000
VERIFIER = "A" * 43  # public synthetic verifier; real clients generate high entropy values
REDIRECT = "https://client.example/callback"


def challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def issued_code():
    return {"value": "synthetic-code-1", "client_id": "client-a", "redirect_uri": REDIRECT,
            "challenge": challenge(VERIFIER), "method": "S256", "expires": NOW + 60,
            "used": False}


def redeem(record, verifier, *, fixed, client_id="client-a", redirect_uri=REDIRECT, now=NOW):
    if record["used"] or now >= record["expires"]:
        return False
    if client_id != record["client_id"] or redirect_uri != record["redirect_uri"]:
        return False
    if fixed:
        if not isinstance(verifier, str) or not 43 <= len(verifier) <= 128:
            return False
        if any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~" for c in verifier):
            return False
        if record["method"] != "S256" or not hmac.compare_digest(challenge(verifier), record["challenge"]):
            return False
    record["used"] = True
    return True


def demo():
    return {"attack": "Redeem an intercepted synthetic authorization code without its verifier",
            "vulnerable_accepts": redeem(issued_code(), "wrong", fixed=False),
            "fixed_accepts": redeem(issued_code(), "wrong", fixed=True),
            "legitimate_accepts": redeem(issued_code(), VERIFIER, fixed=True),
            "boundary": "In-memory token-endpoint model; not a full OAuth server"}


if __name__ == "__main__":
    print(json.dumps(demo(), indent=2))
