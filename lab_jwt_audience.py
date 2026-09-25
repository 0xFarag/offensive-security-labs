"""Signed token substitution across services; fixed public lab key, no network."""
import base64
import hashlib
import hmac
import json

KEY = b"PUBLIC-LAB-KEY-NEVER-USE-IN-PRODUCTION"
NOW = 1800000000
ISSUER = "https://issuer.example"
AUDIENCE = "portfolio-api"


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def issue(claims, algorithm="HS256"):
    header = b64(json.dumps({"alg": algorithm, "typ": "JWT"}).encode())
    body = b64(json.dumps(claims, sort_keys=True).encode())
    message = f"{header}.{body}"
    return message + "." + b64(hmac.digest(KEY, message.encode(), "sha256"))


def claims(**changes):
    return {"iss": ISSUER, "aud": AUDIENCE, "sub": "demo-user", "exp": NOW + 60, **changes}


def verify(token, *, fixed, now=NOW):
    """Minimal HS256 fixture verifier; deliberately not a production JWT library."""
    try:
        head, body, signature = token.split(".")
        decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        header = json.loads(decode(head))
        payload = json.loads(decode(body))
        if header.get("alg") != "HS256":
            return False
        expected = b64(hmac.digest(KEY, f"{head}.{body}".encode(), "sha256"))
        if not hmac.compare_digest(signature, expected):
            return False
        if not fixed:
            return True  # BUG: a signature alone says nothing about the intended service.
        audience = payload.get("aud")
        audience_ok = audience == AUDIENCE or (
            isinstance(audience, list) and all(isinstance(x, str) for x in audience)
            and AUDIENCE in audience
        )
        return (payload.get("iss") == ISSUER and audience_ok
                and isinstance(payload.get("sub"), str) and bool(payload["sub"])
                and type(payload.get("exp")) in (int, float) and payload["exp"] > now)
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        return False


def demo():
    token = issue(claims(aud="other-service"))
    return {"attack": "Replay a validly signed token issued for another audience",
            "token": token, "decoded_claims": claims(aud="other-service"),
            "vulnerable_accepts": verify(token, fixed=False),
            "fixed_accepts": verify(token, fixed=True),
            "legitimate_accepts": verify(issue(claims()), fixed=True)}


if __name__ == "__main__":
    print(json.dumps(demo(), indent=2))
