# 05 — Pull-request metadata becomes shell syntax

**Scope:** a local POSIX shell modelling expression interpolation into a CI script. **Entry:** a synthetic pull-request title. **Precondition:** untrusted title text is inserted into shell source before execution.

```bash
python3 lab_ci_injection.py
```

The shipped title closes a quote and writes `CI_LAB_MARKER` to `proof.txt` inside a temporary directory. The vulnerable execution creates the marker. The fixed execution prints the complete title literally and creates no file.

**Impact demonstrated:** control over data becomes command execution in the fixture process. No GitHub runner, repository secret or external connection is involved. The function accepts only the two shipped titles.

**Fix:** put the untrusted value in an environment variable and expand it as a quoted argument to a constant script. Avoid `eval` or rebuilding shell source from that value. Runner permissions and event trust remain separate concerns.

**Retest:** the malicious title is preserved literally after the fix; a normal documentation title also retains its exact content.

**Limit:** this models the shell boundary, not GitHub event dispatch, token permissions or a compromised action. The deliberately vulnerable example is not installed under `.github/workflows` and never executes in CI automatically.

**Reference:** [GitHub secure use: intermediate environment variables](https://docs.github.com/en/actions/reference/security/secure-use).
