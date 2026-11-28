"""Serve a signed webhook fixture with a CA trusted only by the child test."""
from contextlib import ExitStack
import base64
import hashlib
import hmac
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        self.server.deliveries.append(self.path)
        body = self.rfile.read(int(self.headers["Content-Length"]))
        message = self.headers["webhook-id"]
        timestamp = self.headers["webhook-timestamp"]
        signed = f"{message}.{timestamp}.".encode() + body
        mac = base64.b64encode(hmac.digest(b"fixture", signed, hashlib.sha256)).decode()
        assert self.headers["webhook-signature"] == "v1," + mac
        assert self.path == "/events" and body == b'{"event":"fixture"}'
        assert message == "msg_" + "0" * 32
        assert self.headers["Host"] == f"{self.server.hostname}:{self.server.server_port}"
        self.send_response(503 if len(self.server.deliveries) == 1 else 202)
        self.end_headers()
        self.wfile.write(b"received")


def exercise(root, command):
    def openssl(*args):
        subprocess.run(["openssl", *args], cwd=root, check=True, capture_output=True)

    isolated = "PYLOROS_TEST_ISOLATED_NETWORK" in os.environ
    address, hostname = ("192.0.0.9", "receiver.test") if isolated else ("127.0.0.1", "localhost")
    if isolated:
        assert [name for _, name in socket.if_nameindex()] == ["lo"]
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=Fixture CA", "-addext", "basicConstraints=critical,CA:TRUE",
            "-keyout", "ca.key", "-out", "ca.pem")
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={hostname}",
            "-keyout", "server.key", "-out", "server.csr")
    (root / "server.ext").write_text(f"subjectAltName=DNS:{hostname}\nextendedKeyUsage=serverAuth\n")
    openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
            "-CAcreateserial", "-days", "1", "-extfile", "server.ext", "-out", "server.pem")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / "server.pem", root / "server.key")
    # Both localhost address families reach the receiver, even if IPv6 resolves first.
    class IPv6Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6

    sni_names = []
    context.set_servername_callback(lambda sock, name, ctx: sni_names.append(name))
    with ExitStack() as stack:
        ipv4 = stack.enter_context(ThreadingHTTPServer((address, 0), Receiver))
        port = ipv4.server_port
        servers = [ipv4]
        if not isolated:
            servers.append(stack.enter_context(IPv6Server(("::1", port), Receiver)))
        deliveries = []
        for server in servers:
            server.deliveries = deliveries
            server.hostname = hostname
            server.socket = context.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            stack.callback(server.shutdown)
        subprocess.run(command, check=True, timeout=45, env={
            **os.environ, "SSL_CERT_FILE": str(root / "ca.pem"),
            "PYLOROS_TEST_TLS_PORT": str(port),
        })
        assert len(deliveries) == 2
        assert sni_names == [None, hostname, hostname], sni_names


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as directory:
        exercise(Path(directory), [sys.argv[1], "--exact", sys.argv[2], "--nocapture"])
