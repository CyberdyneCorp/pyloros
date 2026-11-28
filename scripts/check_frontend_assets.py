"""Compare the public assets served by a console with its reviewed build/client directory."""
import argparse
from http.client import HTTPConnection, HTTPException, HTTPSConnection
import json
from pathlib import Path
from urllib.parse import quote, urlsplit

from check_frontend_build import build_files


def compare_asset(client, target, path, asset):
    client.request("GET", target, headers={"Accept-Encoding": "identity"})
    with client.getresponse() as response:
        if response.status != 200:
            raise ValueError(f"{asset} returned HTTP {response.status}")
        with path.open("rb") as reviewed:
            for chunk in iter(lambda: reviewed.read(65536), b""):
                if response.read(len(chunk)) != chunk:
                    raise ValueError(f"Served content differs for {asset}")
        if response.read(1):
            raise ValueError(f"Served content exceeds the reviewed length for {asset}")


def check(directory: Path, base: str) -> dict:
    url = urlsplit(base)
    if url.scheme not in ("http", "https") or not url.hostname or url.username is not None:
        raise ValueError("Expected an HTTP or HTTPS console URL without credentials")
    if url.query or url.fragment:
        raise ValueError("Console URL must omit query and fragment")
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Expected a reviewed frontend client directory")
    connect = HTTPSConnection if url.scheme == "https" else HTTPConnection
    client = connect(url.hostname, url.port, timeout=10)
    count = 0
    try:
        for path in build_files(directory):
            asset = path.relative_to(directory).as_posix()
            target = url.path.rstrip("/") + "/" + quote(asset)
            compare_asset(client, target, path, asset)
            count += 1
    finally:
        client.close()
    if not count:
        raise ValueError("Reviewed client directory contains no files")
    return {"verified_assets": count}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("base_url")
    args = parser.parse_args()
    try:
        print(json.dumps(check(args.directory, args.base_url)))
    except (OSError, HTTPException, ValueError) as error:
        parser.exit(1, f"{error}\n")
