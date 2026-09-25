# Offensive Security Labs — 0xFarag

**Nine reproducible exploit/fix pairs · 49 regression tests · reviewed 25 September 2026**

Small, inspectable security assessments for Web/API, identity, AI tooling and delivery pipelines. Start with an attacker-controlled input, observe a concrete effect, apply a narrow control, then check that authorized use still works.

**Start in five minutes:** run [SSRF](CASE_04_SSRF.md) or [CI injection](CASE_05_CI.md), compare the before/after evidence, then try a [community challenge](CHALLENGES.md). Looking for peer review, additional regression cases and collaborators on the [next project](ROADMAP.md).

**Nasser Aldin Farag** · [GitHub](https://github.com/0xFarag) · [LinkedIn](https://www.linkedin.com/in/nasser-aldin-farag-974697412/)

## Run the showcase

Python **3.12+** and a POSIX system with `/bin/sh`; standard library only, no packages, API keys or external services.

```bash
git clone https://github.com/0xFarag/offensive-security-labs.git
cd offensive-security-labs
python3 run_all.py
```

The runner executes 49 regression test methods and nine demonstrations. It exits unsuccessfully if an exploit effect, its prevention or its legitimate control differs from the expected result. It rewrites [evidence.json](evidence.json) with the runtime, UTC timestamp, source hashes and observed results. The committed evidence was recorded on Python 3.12.14 / Linux; other platforms are not claimed as tested.

Each lab also runs independently, for example `python3 lab_ssrf_redirect.py`. There is no remote-target option. HTTP uses temporary servers on `127.0.0.1`; the shell and archive cases use temporary directories. The archive traversal intentionally escapes one child directory but stays inside its disposable outer sandbox.

## Choose a case

| Lab / source | Demonstrated effect | Fixed boundary | Case study |
| --- | --- | --- | --- |
| [JWT audience](lab_jwt_audience.py) | Another service's signed token is accepted | Signature **and** issuer/audience/expiry | [01](CASE_01_JWT.md) |
| [OAuth PKCE](lab_oauth_pkce.py) | Intercepted code is redeemed without its verifier | S256 verifier binding | [02](CASE_02_OAUTH.md) |
| [MCP proxy consent](lab_mcp_consent.py) | Upstream consent is reused for a different client | User + client + scope grant | [03](CASE_03_MCP.md) |
| [SSRF redirect](lab_ssrf_redirect.py) | Allowed origin redirects to internal fixture content | Validate the redirect destination | [04](CASE_04_SSRF.md) |
| [CI script injection](lab_ci_injection.py) | PR-title text creates a shell marker file | Pass input as data, not shell source | [05](CASE_05_CI.md) |
| [Archive traversal](lab_tar_traversal.py) | Tar entry writes outside extraction directory | Explicit data filter and file-type policy | [06](CASE_06_ARCHIVE.md) |
| [API mass assignment](lab_api_mass_assignment.py) | A member changes their own role to admin | Editable-property allowlist | [07](CASE_07_API.md) |
| [AI tool boundary](lab_agent_tool_boundary.py) | A malicious proposed tool call is authorized | Tool, argument and resource policy | [08](CASE_08_AGENT.md) |
| [Webhook replay](lab_webhook_replay.py) | One signed event produces two business effects | Freshness plus event-ID deduplication | [09](CASE_09_WEBHOOK.md) |

## What is measured

- **Real mechanisms:** JWT HMAC checks, PKCE hashing, loopback HTTP redirects, POSIX shell interpretation, tar extraction and webhook signatures actually execute.
- **Application/policy fixtures:** authorization, consent, profile changes and webhook business effects use synthetic in-memory state.
- **AI case:** a deterministic malicious tool-call fixture tests the dispatcher. No LLM is called; this is not evidence of a model jailbreak or an attack-success rate.
- **Limits:** no live customer assessment, CVE reproduction, production hardening claim or full OAuth/MCP implementation. The token examples are intentionally minimal; production systems should use maintained protocol libraries and deployment-specific controls.

All samples were prepared with AI assistance and tested locally. [Sources and current relevance](CURRENT_TOPICS.md) distinguish recent guidance from long-established vulnerability classes. [Interview walkthrough](INTERVIEW_GUIDE.md) explains the reasoning behind each fix.

## Recorded outcome

| Gate | Result |
| --- | --- |
| Vulnerable effects reproduced | 9 / 9 |
| Fixed variants deny the attack | 9 / 9 |
| Legitimate controls continue to work | 9 / 9 |
| Regression tests | 49 passed, 0 failures, 0 errors, 0 skipped |

These counts describe the committed local run, not coverage of every possible attack. Inspect the negative cases in [test_security_boundaries.py](test_security_boundaries.py), including token tampering, code replay, scope expansion, redirect destination denial, argument smuggling and rejected-update atomicity.

## Weiterführend

Für eine kurze Durchsicht: zuerst SSRF oder CI-Injection ausführen, danach die Fallstudie und den Fix vergleichen. Für ein technisches Gespräch: JWT/PKCE/MCP zusammen betrachten und erklären, weshalb Signatur, Identität, Audience und Einwilligung unterschiedliche Prüfungen benötigen.

Related work: [API Authorization Lab](https://github.com/0xFarag/api-authorization-lab) · [Nmap Evidence Report](https://github.com/0xFarag/nmap-evidence-report) · [Pentest Case Study](https://github.com/0xFarag/pentest-case-study)

## Build on this

Found a missed edge case? Open an issue with the lab name, Python/OS version, command, expected result and observed result. Small, reproducible findings and focused pull requests are especially useful. See [contribution notes](CONTRIBUTING.md) and the [roadmap](ROADMAP.md). Collaboration enquiries: [LinkedIn](https://www.linkedin.com/in/nasser-aldin-farag-974697412/).
