# Community challenges

Try these after reproducing the baseline. Each challenge has a concrete review target; none requires a public target or someone else's credentials.

| Challenge | Question | Useful contribution |
| --- | --- | --- |
| Audience is a list | What happens when the expected audience appears alongside another value? | A test for malformed audience types and a documented policy decision |
| Code lifecycle | Should a failed PKCE attempt consume a code, and what abuse trade-off follows? | A short threat model with tests for the chosen behaviour |
| Redirect chain | Can an allowed redirect hide a second forbidden hop? | A third local fixture hop, with an unchanged protected-backend counter |
| CI quoting | Why does the injected semicolon execute before the fix but remain text after it? | Explain the parsing stages using the shipped marker payload |
| Atomic updates | Could a rejected profile update still change a permitted field? | A regression proving all-or-nothing behaviour |
| Agent scope | Can an allowed tool name carry an unapproved argument or resource? | A synthetic call that exercises the policy without any real tool execution |
| Duplicate delivery | What changes when two workers receive the same signed event simultaneously? | A transactional fixture showing one business effect |
| Archive lifecycle | What remains on disk if the third member is rejected? | A temporary multi-member fixture and explicit cleanup expectations |

Open an issue with your reasoning or a focused pull request. Link the relevant case study and report the exact local result, including an unexpected failure. See [CONTRIBUTING.md](CONTRIBUTING.md).
