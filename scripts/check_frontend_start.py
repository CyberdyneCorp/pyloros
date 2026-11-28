"""Start the local console image with its shipped command and verify the login page."""
import argparse
import json
from time import monotonic, sleep
import subprocess

from check_frontend_image import docker, local_image_id


PROBE = """
const response = await fetch('http://127.0.0.1:3001/login', {
    redirect: 'manual', signal: AbortSignal.timeout(2000)
});
const type = response.headers.get('content-type') || '';
if (response.status !== 200 || !/^text\\/html(?:;|$)/i.test(type)
    || !/<html(?:\\s|>)/i.test(await response.text())) process.exit(1);
"""


def check(image):
    image_id = local_image_id(image)
    cid = docker("create", "--network", "none", image_id)
    try:
        docker("start", cid)
        deadline = monotonic() + 30
        while monotonic() < deadline:
            if docker("inspect", "--format", "{{.State.Running}}", cid) != "true":
                raise ValueError("Console stopped before serving the login page")
            result = subprocess.run(
                ["docker", "exec", cid, "node", "--input-type=module", "-e", PROBE],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if result.returncode == 0:
                return {"image_id": image_id, "path": "/login", "status": 200}
            sleep(0.5)
        raise ValueError("Console did not serve an HTML login page within 30 seconds")
    finally:
        docker("rm", "--force", "-v", cid)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runtime_image")
    args = parser.parse_args()
    try:
        print(json.dumps(check(args.runtime_image), indent=2))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"{error}\n")
