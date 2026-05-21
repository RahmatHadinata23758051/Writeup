#!/usr/bin/env python3
import re
import socket


HOST = "tjc.tf"
PORT = 31004
CORRECT_TOKENS = {"1A2B", "00FA", "9C4F", "88D1"}
TOKEN_RE = re.compile(rb"0x([0-9A-F]{4})")


def recv_until(sock: socket.socket, buf: bytes, marker: bytes) -> tuple[bytes, bytes]:
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("connection closed before prompt")
        buf += chunk
    return buf.split(marker, 1)


def main() -> None:
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        sock.settimeout(5)
        buf = b""

        for stage in range(1, 5):
            prompt = f"Enter choice for stage {stage} (1-10): ".encode()
            screen, buf = recv_until(sock, buf, prompt)
            tokens = [token.decode() for token in TOKEN_RE.findall(screen)]
            choice = next(i for i, token in enumerate(tokens, 1) if token in CORRECT_TOKENS)
            sock.sendall(f"{choice}\n".encode())

        result = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except TimeoutError:
                break
            if not chunk:
                break
            result += chunk

    print(result.decode(errors="replace").strip())


if __name__ == "__main__":
    main()
