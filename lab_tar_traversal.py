"""Archive extraction boundary; the traversal marker stays inside a disposable outer sandbox."""
import io
import json
from pathlib import Path
import tarfile
import tempfile


def archive_bytes(kind):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        if kind == "symlink":
            member = tarfile.TarInfo("link")
            member.type = tarfile.SYMTYPE
            member.linkname = "../outside.txt"
            archive.addfile(member)
        elif kind in ("traversal", "normal"):
            content = b"TAR_LAB_MARKER"
            member = tarfile.TarInfo("../outside.txt" if kind == "traversal" else "report.txt")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        else:
            raise ValueError("unknown fixture")
    return stream.getvalue()


def strict_filter(member, destination):
    member = tarfile.data_filter(member, destination)
    if member is not None and not (member.isfile() or member.isdir()):
        raise tarfile.FilterError("only regular files and directories are allowed")
    return member


def extract_fixture(kind, *, fixed):
    with tempfile.TemporaryDirectory(prefix="archive-lab-") as outer:
        destination = Path(outer, "extracted")
        destination.mkdir()
        rejected = False
        with tarfile.open(fileobj=io.BytesIO(archive_bytes(kind)), mode="r:") as archive:
            try:
                members = archive.getmembers()
                if len(members) > 10 or sum(m.size for m in members) > 1024:
                    raise tarfile.FilterError("fixture limits exceeded")
                archive.extractall(destination, members=members,
                                   filter=strict_filter if fixed else "fully_trusted")
            except tarfile.FilterError:
                rejected = True
        return {"rejected": rejected, "escaped_extraction_directory": Path(outer, "outside.txt").exists(),
                "normal_file_present": (destination / "report.txt").exists(),
                "symlink_present": (destination / "link").is_symlink()}


def demo():
    vulnerable = extract_fixture("traversal", fixed=False)
    fixed = extract_fixture("traversal", fixed=True)
    return {"attack": "Extract a ../ archive entry outside the intended child directory",
            "vulnerable_accepts": vulnerable["escaped_extraction_directory"],
            "fixed_accepts": fixed["escaped_extraction_directory"],
            "legitimate_accepts": extract_fixture("normal", fixed=True)["normal_file_present"],
            "before": vulnerable, "after": fixed,
            "boundary": "All writes, including the traversal marker, remain in one temporary sandbox"}


if __name__ == "__main__":
    print(json.dumps(demo(), indent=2))
