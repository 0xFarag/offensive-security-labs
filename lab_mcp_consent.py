"""Per-client consent isolation in an MCP-style OAuth proxy: a policy model."""
import json

CLIENTS = {"trusted-editor": "https://editor.example/callback",
           "untrusted-client": "https://untrusted.example/callback"}
GRANTS = {("alice", "trusted-editor"): frozenset({"notes:read"})}


def authorize(user, client, scopes, redirect_uri, *, upstream_cookie=True, fixed):
    if client not in CLIENTS or redirect_uri != CLIENTS[client]:
        return False
    if not upstream_cookie:
        return False  # this fixture only models the returning-user flow
    if not fixed:
        return True  # BUG: consent to a shared upstream client is treated as universal.
    return (user, client) in GRANTS and set(scopes) <= GRANTS[(user, client)]


def demo():
    args = ("alice", "untrusted-client", ["notes:read"], CLIENTS["untrusted-client"])
    return {"attack": "Reuse upstream consent with a different dynamically registered client",
            "vulnerable_accepts": authorize(*args, fixed=False),
            "fixed_accepts": authorize(*args, fixed=True),
            "legitimate_accepts": authorize("alice", "trusted-editor", ["notes:read"],
                                             CLIENTS["trusted-editor"], fixed=True),
            "boundary": "Consent-policy simulation; no real codes, sessions or MCP transport"}


if __name__ == "__main__":
    print(json.dumps(demo(), indent=2))
