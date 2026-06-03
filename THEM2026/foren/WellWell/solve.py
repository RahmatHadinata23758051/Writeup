#!/usr/bin/env python3
import re
import socket


HOST = "45.130.164.173"
PORT = 30203

ANSWERS = {
    "A1: ": "acme-util",
    "A2: ": "/home/ztz/dev/site/node_modules/acme-util/13fa9e8fd23400de798f72da608a8dbf.js",
    "A3: ": "/home/ztz/dev/site/.git/hooks/post-commit",
    "A4: ": "192.168.18.144:1337",
    "A5: ": "2b997a77b33d893acba0c60e609ff7bf:138e100e33926c9a",
    "A6: ": "AES-CBC",
    "A7: ": "0123456789abcdef0123456789abcdef:abcdef0123456789",
}


def recv_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def main():
    with socket.create_connection((HOST, PORT)) as sock:
        sock.settimeout(5)

        for prompt, answer in ANSWERS.items():
            text = recv_until(sock, prompt.encode()).decode(errors="replace")
            print(text, end="")
            sock.sendall((answer + "\n").encode())

        rest = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                rest += chunk
        except TimeoutError:
            pass

        output = rest.decode(errors="replace")
        print(output, end="")

        match = re.search(r"(THEM\?!CTF\{.*\})", output)
        if match:
            print(f"\n<FLAG>{match.group(1)}</FLAG>")


if __name__ == "__main__":
    main()
