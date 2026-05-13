#!/usr/bin/env python3
import json
import socket
from datetime import datetime

HOST = "10.42.5.10"
PORT = 1337
TIME_FORMAT = "%Y-%m-%dT%H:%M"


def recv_all(host: str, port: int) -> bytes:
    data = bytearray()
    with socket.create_connection((host, port), timeout=5) as sock:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
    return bytes(data)


def decode_flag(payload: dict) -> str:
    encoded = [m for m in payload["employees"][0]["meetings"] if m.get("encoded")]
    chars = []
    for meeting in encoded:
        start = datetime.strptime(meeting["start"], TIME_FORMAT)
        end = datetime.strptime(meeting["end"], TIME_FORMAT)
        duration = int((end - start).total_seconds() // 60)
        chars.append(chr(duration))
    return "".join(chars)


def main() -> None:
    raw = recv_all(HOST, PORT)
    payload = json.loads(raw)
    print(decode_flag(payload))


if __name__ == "__main__":
    main()
