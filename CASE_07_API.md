# 07 — Owning a profile does not permit becoming admin

**Scope:** a profile-update application service. **Entry:** an otherwise valid update with the extra property `role: admin`. **Precondition:** the caller owns the profile, but the service blindly copies supplied properties.

```bash
python3 lab_api_mass_assignment.py
```

The vulnerable branch changes the fixture's role from `member` to `admin`. The fixed branch returns status `400` and preserves the original object. A display-name-only update still succeeds.

**Impact demonstrated:** property-level privilege escalation despite a correct object-ownership check. This complements the separate BOLA repository, which focuses on access to another user's object.

**Fix:** define an explicit set of user-editable properties and validate their value types and bounds. Reject the whole update when a forbidden property is supplied; do not partially apply the allowed fields before discovering the problem.

**Retest:** other-user updates fail with `403`; mixed allowed/forbidden updates are atomic; empty names, wrong types and attempts to change the ID fail.

**Limit:** actor identity is supplied by the fixture, not authenticated over HTTP. There is no database or administrator update flow. Authorization must be enforced again wherever equivalent state changes are possible.

**Reference:** [OWASP API3:2023 — Broken Object Property Level Authorization](https://api-security.owasp.org/editions/2023/en/0xa3-broken-object-property-level-authorization/).
