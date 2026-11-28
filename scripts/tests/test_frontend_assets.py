"""Exercise the ingress asset check against a local static file server."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from threading import Thread
import unittest
from unittest.mock import patch
from email.message import Message

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_frontend_assets import check, check_content_type


class QuietHandler(SimpleHTTPRequestHandler):
    content_encodings = ()

    def do_GET(self):
        tag = 'W/"reviewed"'
        if self.headers.get("If-None-Match") == tag and self.path.endswith(".js"):
            self.send_response(304)
            self.end_headers()
            return
        super().do_GET()

    def end_headers(self):
        if self.path.endswith(".js"):
            self.send_header("ETag", 'W/"reviewed"')
        for encoding in self.content_encodings:
            self.send_header("Content-Encoding", encoding)
        super().end_headers()

    def log_message(self, *args):
        pass


class ServedAssets(unittest.TestCase):
    def test_browser_asset_types(self):
        for suffix, values, accepted in [
            (".mjs", ["Application/Javascript; charset=UTF-8"], True),
            (".JS", ["text/javascript"], True),
            (".js", [], False),
            (".js", ["text/javascript; charset=utf-8", "text/plain"], False),
            (".js", ["text/javascript", "text/javascript"], True),
            (".js", ["text/plain", "text/javascript"], True),
            (".css", ["text/css; charset=UTF-8"], True),
            (".css", ["application/octet-stream"], False),
            (".png", [], True),
        ]:
            with self.subTest(suffix=suffix, values=values):
                headers = Message()
                for value in values:
                    headers["Content-Type"] = value
                if accepted:
                    check_content_type("fixture" + suffix, suffix, headers)
                else:
                    with self.assertRaisesRegex(ValueError, "invalid Content-Type"):
                        check_content_type("fixture" + suffix, suffix, headers)

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
                tags = check(reviewed, base, record=True)["asset_etags"]
                self.assertEqual(tags, {name: 'W/"reviewed"'})
                self.assertEqual(check(reviewed, base, baseline=tags)["revalidated_assets"], 1)
                with self.assertRaisesRegex(ValueError, "HTTP 200 for the recorded ETag"):
                    check(reviewed, base, baseline={name: '"earlier"'})
                with self.assertRaisesRegex(ValueError, "Invalid ETag"):
                    check(reviewed, base, baseline={name: "*"})
                with self.assertRaisesRegex(ValueError, "asset paths differ"):
                    check(reviewed, base, baseline={})
                for directory in (public, reviewed):
                    (directory / "untagged.txt").write_text("static")
                mixed = check(reviewed, base, record=True)["asset_etags"]
                self.assertIsNone(mixed["untagged.txt"])
                self.assertEqual(check(reviewed, base, baseline=mixed), {"verified_assets": 2, "revalidated_assets": 1})
                for directory in (public, reviewed):
                    (directory / "untagged.txt").unlink()
                with patch.object(QuietHandler, "guess_type", return_value="text/plain"):
                    with self.assertRaisesRegex(ValueError, "invalid Content-Type"):
                        check(reviewed, base)
                for values in [("gzip",), ("identity", "br"), ("gzip, identity",)]:
                    with self.subTest(values=values), patch.object(QuietHandler, "content_encodings", values):
                        with self.assertRaisesRegex(ValueError, "Content-Encoding"):
                            check(reviewed, base)
                with patch.object(QuietHandler, "content_encodings", ("Identity",)):
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
