"""Compare the delivered frontend files with a reviewed SHA-256 tree digest."""
import argparse
import hashlib
from pathlib import Path


def build_files(directory: Path):
    for path in sorted(directory.iterdir()):
        if path.is_symlink():
            raise ValueError("frontend build contains a symbolic link")
        if path.is_dir():
            yield from build_files(path)
        elif not path.is_file():
            raise ValueError("expected regular files in frontend build")
        else:
            yield path


def file_digest(path: Path) -> bytes:
    content = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            content.update(chunk)
    return content.digest()


def build_digest(root: Path) -> str:
    tree = hashlib.sha256()
    count = 0
    if root.is_symlink() or not root.is_dir():
        raise ValueError("expected a frontend build directory")
    for path in build_files(root):
        tree.update(path.relative_to(root).as_posix().encode("utf-8"))
        tree.update(b"\0")
        tree.update(file_digest(path))
        count += 1
    if not count:
        raise ValueError("frontend build contains no files")
    return tree.hexdigest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("expected", nargs="?", help="digest recorded for the reviewed build")
    args = parser.parse_args()
    try:
        actual = build_digest(args.directory)
    except (ValueError, OSError) as err:
        parser.exit(1, f"{err}\n")
    if args.expected is not None and actual != args.expected.lower():
        parser.exit(1, f"Frontend build differs. Observed SHA-256 {actual}\n")
    print(actual)
