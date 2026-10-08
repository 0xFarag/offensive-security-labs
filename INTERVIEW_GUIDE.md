# A practical 12-minute walkthrough

1. **One minute — scope.** State that the repository contains synthetic local labs, not customer incidents or a list of discovered CVEs. Explain which mechanisms actually execute and which are policy models.
2. **Three minutes — SSRF.** Run the redirect case. Show the backend request count, identify the second trust boundary, and explain why blocking an initial URL alone misses a redirect.
3. **Three minutes — CI.** Show the marker file result, then the exact literal output after the fix. Explain why quoting an environment expansion differs from inserting input into shell source.
4. **Three minutes — identity.** Compare JWT audience, PKCE verifier binding and MCP consent. Describe the different questions each answers: intended recipient, possession of transaction proof, and client-specific permission.
5. **Two minutes — verification.** Run the regression suite, open the evidence source hashes, and name one limit you would investigate next in a real engagement.

## Questions to be able to answer

- Why is a signed token for another audience still unsuitable?
- Which controls does PKCE complement rather than replace?
- Where should an agent's resource restrictions be enforced?
- How can a successful authentication check coexist with failed authorization?
- What does the unchanged SSRF backend hit count prove, and what does it not prove?
- Why does a webhook need idempotency even when every signature is valid?
- Which archive guarantees depend on Python's version or an explicitly selected filter?

Before presenting a lab as personal expertise, read its code, reproduce it and explain the fix in your own words. The repository shows inspectable work and learning; the evidence does not establish broader production experience.
