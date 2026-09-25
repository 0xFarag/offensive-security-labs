# 01 — A valid signature, the wrong service

**Scope:** synthetic HS256 tokens and two logical services sharing a fixture issuer/key. **Entry:** a token issued for `other-service`. **Precondition:** the resource checks the signature but omits audience validation.

```bash
python3 lab_jwt_audience.py
```

The token is validly signed. The vulnerable verifier returns `true` even though `aud` is `other-service`; the fixed verifier returns `false`. A token for `portfolio-api` still succeeds. Inspect `decoded_claims` and the three acceptance fields in the JSON output.

**Impact demonstrated:** cross-service token substitution. This is not signature forgery, key recovery or account compromise against a real provider.

**Fix:** validate the intended audience together with issuer, expiry, subject and the configured signature algorithm. The regression suite also rejects altered signatures, an unapproved algorithm, expired tokens and missing audiences, and accepts a valid audience array.

**Assessment follow-up:** map token issuance to every receiving resource. Verify that gateways and downstream services agree on the audience rather than assuming that any trusted signature implies authorization.

**Limit:** the public hard-coded key and compact verifier exist only to make the fixture inspectable; they are not production authentication code. The fixture does not cover JWKS rotation, key selection, revocation or all JWT parsing edge cases.

**Reference:** [MCP token passthrough and audience separation](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices).
