"""GitHub Actions-style expression interpolation model using a harmless local shell marker."""
import json
from pathlib import Path
import subprocess
import tempfile

PAYLOAD = 'release"; printf CI_LAB_MARKER > proof.txt; #'
NORMAL = "docs: explain authorization tests"


def run_title(title, *, fixed):
    """Fixture input only. Shell process has a minimal environment and a temporary cwd."""
    if title not in (PAYLOAD, NORMAL):
        raise ValueError("only the two shipped fixture titles are accepted")
    with tempfile.TemporaryDirectory(prefix="ci-injection-lab-") as directory:
        environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PR_TITLE": title}
        script = 'printf "%s\\n" "$PR_TITLE"' if fixed else f'printf "%s\\n" "{title}"'
        completed = subprocess.run(["/bin/sh", "-c", script], cwd=directory, env=environment,
                                   text=True, capture_output=True, timeout=3, check=True)
        marker = Path(directory, "proof.txt")
        return {"marker_created": marker.exists(), "stdout": completed.stdout.rstrip("\n"),
                "marker": marker.read_text() if marker.exists() else None}


def demo():
    vulnerable, fixed = run_title(PAYLOAD, fixed=False), run_title(PAYLOAD, fixed=True)
    normal = run_title(NORMAL, fixed=True)
    return {"attack": "Interpolate an attacker-controlled PR title into shell source",
            "payload": PAYLOAD, "vulnerable_accepts": vulnerable["marker_created"],
            "fixed_accepts": fixed["marker_created"],
            "legitimate_accepts": normal["stdout"] == NORMAL,
            "before": vulnerable, "after": fixed,
            "boundary": "Local POSIX shell; no GitHub Actions runner, tokens or network"}


if __name__ == "__main__":
    print(json.dumps(demo(), indent=2))
