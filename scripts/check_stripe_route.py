"""Check the upstream selected for an unsigned POST to the billing webhook."""

import argparse
from http.client import HTTPConnection, HTTPSConnection, HTTPException
import json
import sys
from urllib.parse import urlsplit
from uuid import uuid4


def sample(url, header, expected):
    request_id = str(uuid4())
    connection_type = HTTPSConnection if url.scheme == "https" else HTTPConnection
    connection = connection_type(url.hostname, url.port, timeout=10)
    try:
        target = url.path or "/"
        if url.query:
            target += "?" + url.query
        connection.request(
            "POST",
            target,
            body=b"{}",
            headers={
                "Content-Type": "application/json",
                "X-Request-ID": request_id,
            },
        )
        response = connection.getresponse()
        upstream = response.getheader(header)
        refused = False
        if response.status == 400:
            try:
                body = response.read(4097)
                refused = len(body) <= 4096 and json.loads(body) == {
                    "error": "invalid signature"
                }
            except ValueError:
                pass
        return dict(
            request_id=request_id,
            status=response.status,
            upstream=upstream,
            signature_refused=refused,
            matches=refused and upstream in expected,
        )
    except (OSError, HTTPException) as error:
        return dict(
            request_id=request_id, transport_error=type(error).__name__, matches=False
        )
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Exact ingress URL for the Stripe webhook")
    parser.add_argument(
        "--upstream-header",
        required=True,
        help="Response field set by ingress from the selected upstream",
    )
    parser.add_argument(
        "--expect",
        action="append",
        required=True,
        help="Accepted upstream identifier (repeat for a pool)",
    )
    parser.add_argument("--attempts", type=int, default=1)
    parser.add_argument(
        "--require-all", action="store_true",
        help="Require a successful sample from every expected upstream",
    )
    args = parser.parse_args()
    url = urlsplit(args.url)
    if url.scheme not in ("https", "http") or not url.hostname:
        parser.error("supply an HTTP or HTTPS webhook URL")
    if args.attempts < 1:
        parser.error("--attempts must be positive")
    samples = [
        sample(url, args.upstream_header, args.expect) for _ in range(args.attempts)
    ]
    print(json.dumps(samples, indent=2))
    if args.require_all:
        observed = {s["upstream"] for s in samples if s["matches"]}
        missing = sorted(set(args.expect) - observed)
        if missing:
            print("Missing upstreams: " + ", ".join(missing), file=sys.stderr)
            return 1
    return 0 if all(s["matches"] for s in samples) else 1


if __name__ == "__main__":
    raise SystemExit(main())
