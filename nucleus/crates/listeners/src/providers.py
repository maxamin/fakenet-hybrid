# Runs FakeNet-NG dynamic response providers (HttpDynamic / TcpDynamic / UdpDynamic), unmodified,
# for the fakenet-hybrid nucleus. Embedded in the binary and run with: python3 -I -c <this> MODE PROVIDER
#
#   http: request JSON on stdin; the raw HTTP response the provider writes goes to stdout
#   tcp:  the connection is a socket on fd 3 (relayed to the client by the nucleus)
#   udp:  the listener's socket is on fd 3; the datagram & peer are in FAKENET_UDP_* variables
import base64
import email.message
import http
import importlib.util
import io
import json
import os
import socket
import sys
from email.utils import formatdate


def load(path, names):
    spec = importlib.util.spec_from_file_location("fakenet_provider", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name in names:
        if hasattr(module, name):
            return getattr(module, name)
    sys.exit(f"{path} has no function {' or '.join(names)}")


class Handler:
    """The parts of http.server.BaseHTTPRequestHandler that FakeNet-NG providers use"""

    server_version = "FakeNet/1.3"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def __init__(self, request):
        self.command = request["method"]
        self.path = request["target"]
        self.request_version = request["version"]
        self.requestline = f"{self.command} {self.path} {self.request_version}"
        self.client_address = (request["peer_host"], request["peer_port"])
        self.headers = email.message.Message()
        for name, value in request["headers"]:
            self.headers[name] = value
        self.body = base64.b64decode(request["body"])
        self.rfile = io.BytesIO(self.body)
        self.wfile = io.BytesIO()

    def date_time_string(self, timestamp=None):
        return formatdate(timestamp, usegmt=True)

    def version_string(self):
        return self.server_version

    def send_response_only(self, code, message=None):
        if message is None:
            try:
                message = http.HTTPStatus(code).phrase
            except ValueError:
                message = ""
        self.wfile.write(f"{self.protocol_version} {code} {message}\r\n".encode("latin-1"))

    def send_response(self, code, message=None):
        self.send_response_only(code, message)
        self.send_header("Server", self.version_string())
        self.send_header("Date", self.date_time_string())

    def send_header(self, keyword, value):
        self.wfile.write(f"{keyword}: {value}\r\n".encode("latin-1"))

    def end_headers(self):
        self.wfile.write(b"\r\n")

    def flush_headers(self):
        pass

    def send_error(self, code, message=None, explain=None):
        body = (message or http.HTTPStatus(code).phrase).encode()
        self.send_response(code, message)
        self.send_header("Content-Length", len(body))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def log_message(self, *args):
        pass

    log_request = log_error = log_message


def main():
    mode, path = sys.argv[1], sys.argv[2]
    if mode == "http":
        request = json.load(sys.stdin)
        handler = Handler(request)
        respond = load(path, ["HandleHttp", "HandleRequest"])
        respond(handler, handler.command, handler.body or None)
        sys.stdout.buffer.write(handler.wfile.getvalue())
    elif mode == "tcp":
        sock = socket.socket(fileno=3)
        sock.settimeout(float(os.environ.get("FAKENET_TIMEOUT", "10")))
        load(path, ["HandleTcp"])(sock)
    elif mode == "udp":
        sock = socket.socket(fileno=3)
        data = base64.b64decode(os.environ["FAKENET_UDP_DATA"])
        peer = (os.environ["FAKENET_UDP_HOST"], int(os.environ["FAKENET_UDP_PORT"]))
        load(path, ["HandleUdp"])(sock, data, peer)
    else:
        sys.exit(f"unknown mode {mode}")


main()
