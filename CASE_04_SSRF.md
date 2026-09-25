# 04 — A safe first hop does not authorize the next hop

**Scope:** two temporary HTTP servers on different loopback ports. **Entry:** `/redirect` on the allowed front service. **Precondition:** a fetcher validates the first origin, then follows redirects without applying the same policy.

```bash
python3 lab_ssrf_redirect.py
```

The front fixture returns a 302 to the backend fixture's `/metadata`. The vulnerable fetch returns `SYNTHETIC_METADATA_ONLY`. The fixed redirect handler denies the second origin before contact. `backend_requests_before_fix` and `backend_requests_after_fix` both remain `1`, proving that the retest did not reach the backend. `/public` still returns normally.

**Impact demonstrated:** a redirect crosses the application's origin allowlist. The metadata name is illustrative; no cloud metadata address, private service or real credential is accessed.

**Fix:** validate every redirect destination or disable redirects when unnecessary. The test's transport separately restricts all requests to its two explicit loopback origins, including in vulnerable mode.

**Limit:** this case does not test DNS rebinding, DNS pinning, alternative IP encodings, IPv6 or a production egress proxy. An origin allowlist for two controlled ports is not a general SSRF prevention library.

**References:** [OWASP SSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) · [MCP discovery/redirect risks](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices).
