"""Compare a local console build-context tar with the reviewed Git tree."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile


def tree_entries(repo, tree):
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", tree):
        raise ValueError("expected a full Git tree object ID")
    git = ["git", "-C", str(repo)]
    if subprocess.check_output([*git, "cat-file", "-t", tree]).strip() != b"tree":
        raise ValueError("expected a Git tree")
    listing = subprocess.check_output([*git, "ls-tree", "-rzt", tree])
    entries = {}
    for line in listing.split(b"\0")[:-1]:
        metadata, name = line.split(b"\t", 1)
        mode, _, oid = metadata.decode("ascii").split()
        entries[os.fsdecode(name)] = (mode, oid)
    return entries


def archive_blob(archive, item, algorithm):
    if item.issym():
        data = os.fsencode(item.linkname)
        return "120000", hashlib.new(algorithm, b"blob %d\0" % len(data) + data).hexdigest()
    if not item.isreg():
        raise ValueError(f"unsupported entry type for {item.name!r}")
    digest = hashlib.new(algorithm, b"blob %d\0" % item.size)
    with archive.extractfile(item) as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return ("100755" if item.mode & 0o100 else "100644"), digest.hexdigest()


def verify(repo, tree, path):
    remaining = tree_entries(repo, tree)
    algorithm = "sha1" if len(tree) == 40 else "sha256"
    files = 0
    with path.open("rb") as stream:
        with tarfile.open(fileobj=stream, mode="r:") as archive:
            for item in archive:
                expected = remaining.pop(item.name, None)
                if expected is None:
                    raise ValueError(f"unexpected or repeated entry {item.name!r}")
                if expected[0] == "040000" and item.isdir():
                    continue
                if archive_blob(archive, item, algorithm) != expected:
                    raise ValueError(f"entry differs from Git tree: {item.name!r}")
                files += 1
        if remaining:
            raise ValueError(f"missing entry {min(remaining)!r}")
        stream.seek(0)
        checksum = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return dict(tree=tree, files=files, archive_sha256=checksum.hexdigest())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    parser.add_argument("tree")
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.repository, args.tree, args.archive), indent=2))
    except (ValueError, OSError, tarfile.TarError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"{error}\n")
