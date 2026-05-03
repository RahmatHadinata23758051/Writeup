#!/usr/bin/env python3
from __future__ import annotations

import socket
import struct
import sys
from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


HOST = "217.26.29.80"
PORT = 31337
PASSWORD = b"chocolate"
SALT = b"a3f7c9b1e2d45608"


def recv_until(sock: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed while reading response")
        data += chunk
    return data


def derive_key(password: bytes, salt: bytes) -> bytes:
    return sha256(password + salt).digest()


def encrypt_command(key: bytes, command: bytes) -> bytes:
    iv = get_random_bytes(16)
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(command, 16))
    payload = iv + ciphertext
    return struct.pack(">I", len(payload)) + payload


def decrypt_response(key: bytes, packet: bytes) -> bytes:
    if len(packet) < 4:
        raise ValueError("short packet")
    length = struct.unpack(">I", packet[:4])[0]
    payload = packet[4 : 4 + length]
    if len(payload) != length:
        raise ValueError("truncated encrypted payload")
    iv = payload[:16]
    ciphertext = payload[16:]
    plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    return unpad(plaintext, 16)


def run_command(host: str, port: int, command: bytes) -> bytes:
    key = derive_key(PASSWORD, SALT)
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.settimeout(5)
        recv_until(sock, b"[SUGAR_PROTOCOL v1.0]\n")
        recv_until(sock, b">>>ENCRYPTED_CHANNEL_ACTIVE<<<\n")
        sock.sendall(encrypt_command(key, command))
        header = recv_exact(sock, 4)
        length = struct.unpack(">I", header)[0]
        payload = recv_exact(sock, length)
    return decrypt_response(key, header + payload)


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    result = run_command(host, port, b"cat flag.txt")
    sys.stdout.buffer.write(result)


if __name__ == "__main__":
    main()
