# Topic selection and primary sources

Research reviewed **25 September 2026**. This is a portfolio curriculum, not a ranking of current attacks or a claim that these samples exploit current product versions. Older foundations are included where they explain present-day systems. The implementation and observations are original synthetic fixtures; sources ground the control principles.

| Theme | Primary reference | Why included / exact limit |
| --- | --- | --- |
| Identity boundaries in MCP | [MCP Security Best Practices, 2025-11-25 edition](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) | Addresses token passthrough, per-client consent and redirect-related SSRF. Labs isolate these boundaries without implementing MCP transport. |
| OAuth code interception | [IETF RFC 9700, January 2025](https://datatracker.ietf.org/doc/html/rfc9700) | Current OAuth security BCP discusses PKCE/S256. The lab models redemption, not the complete browser flow. |
| Agentic AI | [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | Motivates an explicit action boundary after planning. The lab evaluates deterministic policy, not a particular model. |
| CI and software supply chain | [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use) · [OWASP A03:2025](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/) | GitHub documents the intermediate-environment-variable pattern. A03 expands supply-chain attention; this one shell case does not cover all of A03. |
| SSRF | [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | Redirect handling is a distinct validation boundary. Our two-port origin allowlist is a fixture, not general Internet URL validation. |
| Archive handling | [Python tarfile documentation](https://docs.python.org/3/library/tarfile.html#extraction-filters) | Python 3.14 changed the default extraction filter to `data`. We explicitly select filters, so the contrast remains visible on 3.12+. This is not a new tarfile zero-day. |
| API property authorization | [OWASP API3:2023](https://api-security.owasp.org/editions/2023/en/0xa3-broken-object-property-level-authorization/) | Established foundation: owning an object does not authorize editing every property. |
| Signed event replay | [Standard Webhooks specification](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md) | Grounds signed message ID/timestamp/body and freshness; the lab adds single-process deduplication to protect its synthetic effect. |

## Assessment questions

1. **AI integrations:** where does untrusted content become an authorized action? Which tool arguments and resources are enforced outside the planner?
2. **Identity:** for whom was the credential issued, which client did the user approve, and which resource is actually receiving it?
3. **Automation:** can repository metadata become shell syntax or change a build's trust assumptions?
4. **Evidence:** does the proposed fix stop the observed effect while preserving the legitimate use case?

The cases do not include third-party scanning, credential collection, exploit delivery to real systems, or claims about undisclosed vulnerabilities. No target outside the local fixtures was tested.
