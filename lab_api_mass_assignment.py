"""Object ownership alone does not authorize editing every object property."""
import copy
import json

PROFILE = {"id": "alice", "display_name": "Alice", "timezone": "UTC", "role": "member"}
EDITABLE = {"display_name", "timezone"}


def update_profile(profile, actor, patch, *, fixed):
    if actor != profile["id"]:
        return 403, copy.deepcopy(profile)
    if not isinstance(patch, dict):
        return 400, copy.deepcopy(profile)
    if fixed:
        if set(patch) - EDITABLE or any(not isinstance(v, str) or not 1 <= len(v) <= 80 for v in patch.values()):
            return 400, copy.deepcopy(profile)
    updated = copy.deepcopy(profile)
    updated.update(patch)
    return 200, updated


def demo():
    payload = {"display_name": "Alice", "role": "admin"}
    before = update_profile(PROFILE, "alice", payload, fixed=False)
    after = update_profile(PROFILE, "alice", payload, fixed=True)
    legitimate = update_profile(PROFILE, "alice", {"display_name": "Alice F."}, fixed=True)
    return {"attack": "Add a privileged property to an otherwise authorized profile update",
            "payload": payload, "vulnerable_accepts": before[1]["role"] == "admin",
            "fixed_accepts": after[1]["role"] == "admin", "legitimate_accepts": legitimate[0] == 200,
            "before": {"status": before[0], "profile": before[1]},
            "after": {"status": after[0], "profile": after[1]},
            "boundary": "In-process application service; actor identity is a fixture, not authentication"}


if __name__ == "__main__":
    print(json.dumps(demo(), indent=2))
