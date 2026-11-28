import json
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


class CoverageTests(unittest.TestCase):
    def check_route(self, replicas, *flags):
        replies = iter(replicas)

        class Ingress(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(400)
                self.send_header("X-Upstream", next(replies))
                self.end_headers()
                self.wfile.write(b'{"error":"invalid signature"}')

            def log_message(self, *args):
                pass

        with HTTPServer(("127.0.0.1", 0), Ingress) as server:
            worker = threading.Thread(target=server.serve_forever)
            worker.start()
            try:
                probe = Path(__file__).resolve().parents[1] / "check_stripe_route.py"
                return subprocess.run(
                    [sys.executable, probe, f"http://127.0.0.1:{server.server_port}/stripe",
                     "--upstream-header", "X-Upstream", "--expect", "a", "--expect", "b",
                     "--attempts", str(len(replicas)), *flags],
                    capture_output=True, text=True, timeout=10,
                )
            finally:
                server.shutdown()
                worker.join()

    def test_coverage(self):
        for replicas, flags, status, missing in [
            (["a", "a"], [], 0, ""),
            (["a", "a"], ["--require-all"], 1, "Missing upstreams: b"),
            (["b", "a"], ["--require-all"], 0, ""),
            (["b", "other", "a"], ["--require-all"], 1, ""),
        ]:
            with self.subTest(replicas=replicas, flags=flags):
                result = self.check_route(replicas, *flags)
                self.assertEqual(result.returncode, status)
                self.assertEqual(result.stderr.strip(), missing)
                self.assertEqual([s["upstream"] for s in json.loads(result.stdout)], replicas)
