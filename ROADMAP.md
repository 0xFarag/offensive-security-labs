# Follow-up projects

These are **proposals**, not implemented features. Open an issue to discuss a small first slice or contribute a focused test.

| Proposal | First reviewable deliverable | Evidence of completion |
| --- | --- | --- |
| MCP authorization integration lab | Replace the consent-policy model with an isolated standards-based test server | Real request/response trace, client isolation and scope tests |
| Agent action-policy evaluation | A documented corpus of synthetic proposed tool calls | Per-case allow/deny results and false-positive analysis; model testing reported separately |
| Webhook concurrency | A transactional idempotency fixture | Concurrent duplicate deliveries produce exactly one committed effect |
| SSRF redirect matrix | Explicitly scoped local redirect chains and parser cases | Allowed and denied routes plus backend-contact evidence |
| Cross-version reproducibility | Test the same lab contract on supported Python versions | Recorded runtime matrix and explained differences |

The first release concentrates on inspectable local cases. The next step is deeper evidence for one boundary at a time, including realistic integration behaviour and failure cases.
