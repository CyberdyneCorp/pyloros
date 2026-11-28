"""Compare the public assets served by a console with its reviewed build/client directory."""
import argparse
import hashlib
from http.client import HTTPConnection, HTTPException, HTTPSConnection
import json
import re
from pathlib import Path
from urllib.parse import quote, urlsplit
from uuid import uuid4

from check_frontend_build import build_files


# JavaScript MIME type essences from https://mimesniff.spec.whatwg.org/#javascript-mime-type
JAVASCRIPT_TYPES = {
    "application/ecmascript", "application/javascript", "application/x-ecmascript",
    "application/x-javascript", "text/ecmascript", "text/javascript", "text/javascript1.0",
    "text/javascript1.1", "text/javascript1.2", "text/javascript1.3", "text/javascript1.4",
    "text/javascript1.5", "text/jscript", "text/livescript", "text/x-ecmascript", "text/x-javascript",
}
BROWSER_TYPES = {".js": JAVASCRIPT_TYPES, ".mjs": JAVASCRIPT_TYPES, ".css": {"text/css"}}


def check_content_type(asset, suffix, headers):
    accepted = BROWSER_TYPES.get(suffix.lower())
    if accepted is None:
        return
    values = headers.get_all("Content-Type", [])
    # Browsers use the last supplied Content-Type when a response repeats the field.
    if not values or values[-1].partition(";")[0].strip().lower() not in accepted:
        raise ValueError(f"{asset} has an invalid Content-Type for {suffix}: {values!r}")


def compare_asset(client, target, path, asset, *, stale_tag=None):
    headers = {"Accept-Encoding": "identity"}
    if stale_tag is not None:
        headers["If-None-Match"] = stale_tag
    client.request("GET", target, headers=headers)
    with client.getresponse() as response:
        if response.status != 200:
            context = " for a nonmatching ETag" if stale_tag is not None else ""
            raise ValueError(f"{asset} returned HTTP {response.status}{context}")
        encodings = response.headers.get_all("Content-Encoding", [])
        for value in encodings:
            if any(coding.strip().lower() != "identity" for coding in value.split(",") if coding.strip()):
                raise ValueError(f"{asset} has incompatible Content-Encoding for an identity request: {encodings!r}")
        check_content_type(asset, path.suffix, response.headers)
        digest = hashlib.sha256()
        with path.open("rb") as reviewed:
            for chunk in iter(lambda: reviewed.read(65536), b""):
                if response.read(len(chunk)) != chunk:
                    raise ValueError(f"Served content differs for {asset}")
                digest.update(chunk)
        if response.read(1):
            raise ValueError(f"Served content exceeds the reviewed length for {asset}")
        return response.headers.get("ETag"), digest.digest()


def validate_tags(tags):
    if not isinstance(tags, dict):
        raise ValueError("Expected an asset_etags object")
    for asset, tag in tags.items():
        if tag is None:
            continue
        if not isinstance(tag, str) or not re.fullmatch(r'(?:W/)?"[!#-~\x80-\xff]*"', tag):
            raise ValueError(f"Invalid ETag for {asset}")


def revalidate(client, target, tag, asset):
    client.request("GET", target, headers={"Accept-Encoding": "identity", "If-None-Match": tag})
    with client.getresponse() as response:
        if response.status != 304:
            raise ValueError(f"{asset} returned HTTP {response.status} for the recorded ETag")


def console_url(base):
    url = urlsplit(base)
    if url.scheme not in ("http", "https") or not url.hostname or url.username is not None:
        raise ValueError("Expected an HTTP or HTTPS console URL without credentials")
    if url.query or url.fragment:
        raise ValueError("Console URL must omit query and fragment")
    return url


def check(directory: Path, base: str, *, record=False, baseline=None, expected_digest=None) -> dict:
    url = console_url(base)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Expected a reviewed frontend client directory")
    connect = HTTPSConnection if url.scheme == "https" else HTTPConnection
    client = connect(url.hostname, url.port, timeout=10)
    tags = {}
    tree = hashlib.sha256()
    revalidated = 0
    if baseline is not None:
        validate_tags(baseline)
    try:
        for path in build_files(directory):
            asset = path.relative_to(directory).as_posix()
            target = url.path.rstrip("/") + "/" + quote(asset)
            tags[asset], digest = compare_asset(client, target, path, asset)
            tree.update(asset.encode("utf-8") + b"\0" + digest)
            if baseline is not None and baseline.get(asset) is not None:
                revalidate(client, target, baseline[asset], asset)
                compare_asset(client, target, path, asset, stale_tag=f'"{uuid4()}"')
                revalidated += 1
    finally:
        client.close()
    if not tags:
        raise ValueError("Reviewed client directory contains no files")
    if expected_digest is not None and tree.hexdigest() != expected_digest:
        raise ValueError("Reviewed client bytes differ from the recorded assets")
    report = {"verified_assets": len(tags)}
    if record:
        validate_tags(tags)
        report["asset_etags"] = tags
        report["client_sha256"] = tree.hexdigest()
    if baseline is not None:
        if tags.keys() != baseline.keys():
            raise ValueError("Recorded and reviewed asset paths differ")
        report["revalidated_assets"] = revalidated
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("base_url")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--record-etags", action="store_true")
    modes.add_argument("--replay-etags", type=Path, metavar="REPORT")
    args = parser.parse_args()
    try:
        baseline = None
        expected_digest = None
        if args.replay_etags:
            saved = json.loads(args.replay_etags.read_text())
            if not isinstance(saved, dict) or not isinstance(saved.get("asset_etags"), dict):
                raise ValueError("Expected a recorded asset_etags object")
            baseline = saved["asset_etags"]
            if "client_sha256" in saved:
                expected_digest = saved["client_sha256"]
                if not isinstance(expected_digest, str) or not re.fullmatch("[0-9a-f]{64}", expected_digest):
                    raise ValueError("Invalid recorded client SHA-256")
        print(json.dumps(check(args.directory, args.base_url, record=args.record_etags, baseline=baseline, expected_digest=expected_digest)))
    except (OSError, HTTPException, ValueError) as error:
        parser.exit(1, f"{error}\n")
