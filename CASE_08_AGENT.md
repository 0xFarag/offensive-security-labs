# 08 — An AI-proposed action still needs authorization

**Scope:** a deterministic dispatcher policy. **Entry:** a synthetic malicious planner output proposing `send_report`. **Precondition:** the application treats every well-formed proposed tool call as authorized.

```bash
python3 lab_agent_tool_boundary.py
```

The vulnerable dispatcher records the prohibited action as allowed. The fixed dispatcher denies it because the task permits only `read_note` on `notes/summary.txt`. The permitted read succeeds. All actions are simulated: no file is read and no report is transmitted.

**Impact demonstrated:** a missing enforcement boundary between a proposed action and permission to execute it. This can matter even when malicious input reaches a planner indirectly.

**Fix:** independently enforce the tool, exact argument schema and resource scope. A syntactically valid tool call is not sufficient authorization. Keep task policy outside content supplied by a page, document or planner output.

**Retest:** a different tool, private resource, extra `send_to` argument and malformed path are denied.

**Limit:** this is not a successful prompt injection against an LLM. No model, prompt attack, inference API or actual tool executor is involved, and no attack-success rate is claimed. It isolates the downstream policy that a real agent application would need to enforce.

**Reference:** [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).
