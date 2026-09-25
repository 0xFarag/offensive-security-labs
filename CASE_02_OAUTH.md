# 02 — Intercepted code without its verifier

**Scope:** an in-memory token-endpoint state machine. **Entry:** a synthetic authorization code. **Precondition:** the attacker has the code and knows the public client/redirect values, but lacks the original PKCE verifier.

```bash
python3 lab_oauth_pkce.py
```

Without PKCE enforcement, `wrong` redeems the code. With S256 binding, the same attempt fails; the matching 43-character fixture verifier succeeds. Both variants already enforce client binding, exact redirect equality, expiry and one-time redemption, isolating the missing verifier check.

**Impact demonstrated:** possession of a code becomes sufficient to redeem it when the proof-of-possession step is omitted.

**Fix:** require the original verifier and compare its S256 challenge with the value stored when issuing the code. Refuse a downgrade to `plain`. Keep the other transaction bindings.

**Retest:** wrong client, altered redirect, expiry boundary and code reuse fail. A failed verifier attempt does not consume the legitimate transaction in this model.

**Limit:** no authorization endpoint, TLS, browser callback, state/nonce validation or actual identity provider is implemented. The verifier is deliberately public and deterministic, unlike a real client's random verifier. This is a code-redemption case, not a complete OAuth security assessment.

**Reference:** [IETF RFC 9700, OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700).
