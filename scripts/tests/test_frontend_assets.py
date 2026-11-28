"""Exercise the ingress asset check against a local static file server."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from threading import Thread
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_frontend_assets import check


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class ServedAssets(unittest.TestCase):
    def test_compares_reviewed_files_below_a_mount_path(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            reviewed, public = root / "reviewed", root / "public"
            reviewed.mkdir()
            public.mkdir()
            name = "shared #1.js"
            data = bytes(range(256)) * 300
            (reviewed / name).write_bytes(data)
            asset = public / name
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=tmp))
            thread = Thread(target=server.serve_forever)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_port}/public/"
                asset.write_bytes(data)
                self.assertEqual(check(reviewed, base), {"verified_assets": 1})
                for changed in (data[:-1], data + b"!", data[:-1] + b"!"):
                    asset.write_bytes(changed)
                    with self.assertRaisesRegex(ValueError, "Served content"):
                        check(reviewed, base)
                asset.unlink()
                with self.assertRaisesRegex(ValueError, "HTTP 404"):
                    check(reviewed, base)
                asset.mkdir()
                with self.assertRaisesRegex(ValueError, "HTTP 301"):
                    check(reviewed, base)
            finally:
                server.shutdown()
                thread.join()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
