# 03 — Consent is not transferable between clients

**Scope:** an MCP-style OAuth proxy consent policy. **Entry:** a newly registered client requesting `notes:read`. **Precondition:** Alice previously approved a trusted editor, and the upstream provider remembers consent for the proxy's shared client.

```bash
python3 lab_mcp_consent.py
```

The vulnerable policy accepts `untrusted-client` because an upstream consent cookie exists. The fixed policy denies it: Alice's grant belongs to `trusted-editor`. The approved editor still succeeds.

**Impact demonstrated:** a confused consent decision can authorize the wrong client. The output records a boolean policy decision; it does not mint or steal tokens.

**Fix:** record grants by user and requesting client, constrain requested scopes to the approved grant, and exactly validate registered redirect URIs. Consent at the upstream provider cannot substitute for consent to the actual downstream client.

**Retest:** changing user, expanding the scope to `notes:write`, or appending to the registered redirect URI is rejected.

**Limit:** this is a deterministic consent-policy model, not a running MCP proxy. Client registration, a real consent UI, CSRF/state protection, session lifecycle and persistence remain outside its scope. A deployment review must examine those separately.

**Reference:** [MCP confused-deputy guidance](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices).
