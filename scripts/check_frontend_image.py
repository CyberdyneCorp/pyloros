"""Compare the installed console in local build-stage and runtime-stage images."""
import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from check_frontend_build import file_digest
from check_frontend_runtime import payload_manifest, verify_manifest


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


@contextmanager
def container(image):
    # Pin the local ID so a tag update cannot change the image between checks.
    image_id = docker("image", "inspect", "--format", "{{.Id}}", image)
    cid = docker("create", "--network", "none", "--entrypoint", "node", image_id,
                 "-p", "JSON.stringify([process.version, process.platform, process.arch])")
    try:
        yield cid
    finally:
        docker("rm", "-v", cid)


def inspect(image, lock_required):
    with container(image) as cid, TemporaryDirectory() as tmp:
        root = Path(tmp)
        output = docker("start", "--attach", cid)
        if docker("inspect", "--format", "{{.State.ExitCode}}", cid) != "0":
            raise ValueError("Node failed to start inside the image")
        node = json.loads(output)
        for name in ("build", "package.json", "node_modules"):
            docker("cp", f"{cid}:/app/{name}", str(root / name))
        manifest = {**payload_manifest(root), "node": node}
        if lock_required:
            lock = root / "package-lock.json"
            docker("cp", f"{cid}:/app/package-lock.json", str(lock))
            if lock.is_symlink() or not lock.is_file():
                raise ValueError("Expected a regular build-stage lockfile")
            manifest["package-lock.json"] = file_digest(lock).hex()
        return manifest


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("build_image")
    p.add_argument("runtime_image")
    p.add_argument("expected", nargs="?", type=Path, help="reviewed image manifest")
    args = p.parse_args()
    try:
        build = inspect(args.build_image, True)
        runtime = inspect(args.runtime_image, False)
        changed = [key for key in runtime if runtime[key] != build[key]]
        if changed:
            raise ValueError("Image differs from build stage in " + ", ".join(changed))
        if args.expected is not None:
            verify_manifest(build, args.expected)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        p.exit(1, f"{error}\n")
    print(json.dumps(build, indent=2))
