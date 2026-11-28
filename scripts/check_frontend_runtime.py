"""Record or verify the files and Node runtime used to launch a packaged console."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

from check_frontend_build import build_digest, file_digest


def dependencies(root):
    tree = hashlib.sha256()
    for directory, names, files in os.walk(root, onerror=raise_error):
        names.sort()
        for name in sorted(names + files):
            path = Path(directory) / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                target = os.readlink(path)
                if os.path.isabs(target) or not path.resolve(strict=True).is_relative_to(root):
                    raise ValueError(f"Dependency link cannot be relocated: {path.relative_to(root)}")
                entry = ["link", target]
            elif stat.S_ISDIR(mode):
                entry = ["directory"]
            elif stat.S_ISREG(mode):
                entry = ["file", mode & 0o111, file_digest(path).hex()]
            else:
                raise ValueError(f"Unsupported dependency file: {path.relative_to(root)}")
            record = [path.relative_to(root).as_posix(), *entry]
            tree.update(json.dumps(record, ensure_ascii=True).encode("ascii") + b"\n")
    return tree.hexdigest()


def raise_error(error):
    raise error


def payload_manifest(root):
    root = root.resolve(strict=True)
    for name in ("package.json", "node_modules"):
        path = root / name
        valid = path.is_dir() if name == "node_modules" else path.is_file()
        if path.is_symlink() or not valid:
            raise ValueError(f"Invalid runtime input: {name}")
    return {
        "build": build_digest(root / "build"),
        "package.json": file_digest(root / "package.json").hex(),
        "node_modules": dependencies(root / "node_modules"),
    }


def runtime_manifest(root):
    lock = root / "package-lock.json"
    if lock.is_symlink() or not lock.is_file():
        raise ValueError("Invalid runtime input: package-lock.json")
    node = subprocess.check_output(
        ["node", "-p", "JSON.stringify([process.version, process.platform, process.arch])"], text=True
    )
    return {**payload_manifest(root), "package-lock.json": file_digest(lock).hex(), "node": json.loads(node)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("expected", type=Path, nargs="?")
    args = parser.parse_args()
    try:
        observed = runtime_manifest(args.directory)
        if args.expected is not None:
            expected = json.loads(args.expected.read_text())
            if not isinstance(expected, dict):
                raise ValueError("Expected a runtime manifest object")
            changed = observed.keys() ^ expected.keys()
            changed.update(key for key in observed.keys() & expected.keys() if observed[key] != expected[key])
            if changed:
                raise ValueError("Frontend runtime differs in " + ", ".join(sorted(changed)))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"{error}\n")
    print(json.dumps(observed, indent=2))
