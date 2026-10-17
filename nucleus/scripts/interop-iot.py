#!/usr/bin/env python3
# Minimal, stdlib-only MQTT / CoAP / WebSocket clients for interop.sh: each connects to the
# nucleus on localhost, exchanges one message, and prints OK on success. No third-party
# packages, so CI needs only python3.
import base64
import hashlib
import os
import socket
import struct
import sys


def mqtt(port):
    # MQTT 3.1.1 CONNECT with a username and password, then expect CONNACK (0x20)
    def field(data):
        return struct.pack(">H", len(data)) + data

    payload = field(b"interop-bot") + field(b"iotuser") + field(b"iot-pw")
    variable = field(b"MQTT") + bytes([4, 0xC2]) + struct.pack(">H", 30)  # user+password flags
    body = variable + payload
    packet = bytes([0x10, len(body)]) + body
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(packet)
        connack = s.recv(4)
    assert connack[:1] == b"\x20", connack
    print("OK")


def coap(port):
    # CON GET /.well-known/core: Uri-Path options ".well-known" (11) then "core"
    header = bytes([0x40, 0x01]) + struct.pack(">H", 0x1234)
    def opt(delta, value):
        assert len(value) < 13
        return bytes([(delta << 4) | len(value)]) + value
    datagram = header + opt(11, b".well-known") + opt(0, b"core")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(datagram, ("127.0.0.1", port))
    reply, _ = s.recvfrom(2048)
    s.close()
    # 2.05 Content (0x45) in an ACK (type 2, in bits 4-5 of byte 0)
    assert (reply[0] >> 4) & 3 == 2 and reply[1] == 0x45, reply[:2].hex()
    print("OK")


def ws(port):
    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET /interop HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(request.encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = s.recv(1024)
            if not chunk:
                break
            head += chunk
        assert b" 101 " in head, head[:64]
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        assert accept.encode() in head, "bad Sec-WebSocket-Accept"
        # A masked text frame with the message
        message = b'{"hello":"ws"}'
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(message))
        s.sendall(bytes([0x81, 0x80 | len(message)]) + mask + masked)
    print("OK")


{"mqtt": mqtt, "coap": coap, "ws": ws}[sys.argv[1]](int(sys.argv[2]))
