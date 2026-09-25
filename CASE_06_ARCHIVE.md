# 06 — Archive names are filesystem instructions

**Scope:** a tar archive built in memory and extracted into a child of a temporary directory. **Entry:** the member name `../outside.txt`. **Precondition:** extraction explicitly trusts archive metadata.

```bash
python3 lab_tar_traversal.py
```

The vulnerable extraction writes the harmless marker outside the intended child directory. It remains inside the disposable outer sandbox. The fixed variant rejects that member and leaves no traversal marker; a normal `report.txt` still extracts.

**Impact demonstrated:** archive-controlled paths can change the destination of a write. No host configuration, repository file or unrelated directory is overwritten.

**Fix:** use an explicit `data`-based extraction filter, allow only regular files/directories, and bound the fixture's member count and total size. The regression suite additionally rejects an escaping symlink.

**Current relevance:** Python 3.14 changed the default filter to `data`. The lab deliberately specifies `fully_trusted` for its vulnerable branch, avoiding a misleading claim that current defaults are vulnerable.

**Limit:** production extraction also needs resource limits, careful ownership/permissions, race handling and cleanup after partial failure. This one-entry fixture does not prove safety for every archive type or denial-of-service scenario.

**Reference:** [Python tarfile extraction filters](https://docs.python.org/3/library/tarfile.html#extraction-filters).
