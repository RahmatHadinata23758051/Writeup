#!/usr/bin/env python3
"""Retrieve the challenge flag using the length-prefixed login protocol."""

import socket


HOST = "34.40.133.67"
PORT = 6768


def recv_until_nul(sock):
    data = bytearray()
    while 0 not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def field(value: bytes) -> bytes:
    # The decoder expects a one-byte length, followed by a NUL-terminated value.
    payload = value + b"\x00"
    return bytes([len(payload)]) + payload


def main():
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        recv_until_nul(sock)             # banner / username prompt
        sock.sendall(field(b"admin"))
        recv_until_nul(sock)             # password prompt
        sock.sendall(field(b"password"))
        response = recv_until_nul(sock)
        print(response.rstrip(b"\x00").decode())


if __name__ == "__main__":
    main()
