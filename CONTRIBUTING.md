# Contribute a reproducible security case

Good first contributions are small enough to review end to end: a missing negative test, a clearer case-study explanation, a portability fix, or an additional controlled fixture.

## Open an issue

Use a title such as `SSRF: redirect policy regression on Python 3.x` and include:

1. Lab and relevant source file.
2. OS and Python version.
3. Exact local command and a minimal synthetic fixture.
4. Expected behaviour, observed behaviour, and why the difference matters.
5. Proposed fix or a question for discussion.

For a project idea, describe its attacker capability, the controlled test environment, the effect you intend to measure, and one legitimate use case the fix must preserve. Link a primary reference when claiming current relevance.

## Submit a pull request

- Keep each change focused on one security boundary.
- Add a regression that exposes the problem and preserves an authorized workflow.
- Run `python3 run_all.py`; explain the changed evidence and source hashes.
- Keep fixtures synthetic and local. Do not add customer data, credentials or external-target automation.
- Distinguish a simulation from a tested protocol implementation.

No live exploit is needed to contribute. A precise limitation or failed assumption is useful evidence too. Proposed features remain proposals until reviewed; the roadmap is not a delivery promise.

## Review discussion

Prefer concrete counterexamples over severity labels. Explain the attack preconditions, observed effect and limits of the claim. Severity depends on deployment context; these isolated fixtures do not receive invented production CVSS scores.
