"""Compare public, read-only HTTP contracts on two running deployments."""
import argparse
import json
import sys
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, build_opener

HEALTH = "/api/v1/health"
READY = "/api/v1/health/ready"
DISCOVERY = (
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/jwks.json",
)
HEADERS = (
    "Content-Type",
    "Content-Security-Policy",
    "Referrer-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Permissions-Policy",
    "Strict-Transport-Security",
)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_response(client, base, path):
    try:
        response = client.open(base.rstrip("/") + path, timeout=10)
    except HTTPError as error:
        response = error
    with response:
        body = json.load(response)
        return response.status, {key: response.headers.get(key) for key in HEADERS}, body


def differences(reference, candidate, expected):
    old_status, old_headers, old_body = reference
    new_status, new_headers, new_body = candidate
    issues = []
    if old_status != expected or new_status != expected:
        issues.append(f"expected {expected}, reference {old_status}, candidate {new_status}")
    for key in HEADERS:
        if old_headers[key] != new_headers[key]:
            issues.append(f"header {key}")
    if json.dumps(old_body, sort_keys=True) != json.dumps(new_body, sort_keys=True):
        if isinstance(old_body, dict) and isinstance(new_body, dict):
            fields = old_body.keys() | new_body.keys()
            for key in sorted(fields):
                if key not in old_body or key not in new_body:
                    issues.append(f"field {key}")
                elif json.dumps(old_body[key], sort_keys=True) != json.dumps(new_body[key], sort_keys=True):
                    issues.append(f"field {key}")
        else:
            issues.append("JSON body")
    return issues


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference")
    parser.add_argument("candidate")
    parser.add_argument("--oidc-disabled", action="store_true")
    parser.add_argument("--not-ready", action="store_true")
    args = parser.parse_args()
    expected = {HEALTH: 200, READY: 503 if args.not_ready else 200}
    expected.update(dict.fromkeys(DISCOVERY, 404 if args.oidc_disabled else 200))
    client = build_opener(NoRedirect())
    failed = False
    for path, status in expected.items():
        try:
            old = read_response(client, args.reference, path)
            new = read_response(client, args.candidate, path)
            issues = differences(old, new, status)
        except (ValueError, OSError) as error:
            issues = [f"request or JSON error ({type(error).__name__})"]
        print(f"{path}  {', '.join(issues) if issues else 'PASS'}")
        failed |= bool(issues)
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
