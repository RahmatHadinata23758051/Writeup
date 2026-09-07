#!/usr/bin/env python3
import socket
import ssl
import re
import time
import string
import os

HOST = os.environ.get(
    "HOST", "mid2-78e6619bb7eb02f0.challs.ctf.thefewchosen.com"
)
PORT = int(os.environ.get("PORT", "1337"))

MAX_QUERIES = 195
PASSWORD_LENGTH = 30
ALPHABET = string.digits + string.ascii_uppercase + string.ascii_lowercase
BASE = len(ALPHABET)
N = BASE ** PASSWORD_LENGTH
INIT_QUERIES = (N - 1).bit_length()  # ceil(log2(N)) == 179


class Found(Exception):
    def __init__(self, flag):
        self.flag = flag


def encode_num(x: int) -> str:
    s = []
    for _ in range(PASSWORD_LENGTH):
        s.append(ALPHABET[x % BASE])
        x //= BASE
    return "".join(reversed(s))


def ceil_log2(x: int) -> int:
    return (x - 1).bit_length()


def connect():
    raw = socket.create_connection((HOST, PORT), timeout=8)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = ctx.wrap_socket(raw, server_hostname=HOST)
    sock.settimeout(8)
    return sock


def recv_until(sock):
    data = b""

    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break

        if not chunk:
            break

        data += chunk

        if b"TFCCTF{" in data:
            # grab remaining flag line if any
            try:
                sock.settimeout(1)
                data += sock.recv(4096)
            except Exception:
                pass
            break

        if data.endswith(b"> ") or b"out of queries" in data:
            break

    text = data.decode(errors="ignore")
    m = re.search(r"TFCCTF\{[^}]+\}", text)
    if m:
        raise Found(m.group(0))

    return text


def ask(sock, state: int, guess_num: int) -> str:
    guess = encode_num(guess_num)
    sock.sendall(f"{state} {guess}\n".encode())

    text = recv_until(sock)

    if "equal" in text:
        return "equal"
    if "smaller" in text:
        return "smaller"
    if "larger" in text:
        return "larger"

    raise RuntimeError(f"bad response: {text!r}")


def run_once(attempt: int):
    sock = connect()
    queries = 0

    try:
        recv_until(sock)  # banner + first prompt

        lo, hi = 0, N - 1
        history = [(lo, hi)]

        # Phase 1: assume mood masih 0.
        for _ in range(INIT_QUERIES):
            if lo >= hi:
                break
            if lo > hi:
                break

            mid = (lo + hi) // 2
            ans = ask(sock, 0, mid)
            queries += 1

            if ans == "equal":
                return

            if ans == "smaller":
                lo = mid + 1
            elif ans == "larger":
                hi = mid - 1

            history.append((lo, hi))

        # Kalau binary search state=0 berhasil, submit kandidat.
        if lo == hi and queries < MAX_QUERIES:
            ask(sock, 0, lo)
            queries += 1

        # Kalau belum dapat flag, kemungkinan mood sudah switch.
        # Rollback ke checkpoint paling awal yang masih bisa diselesaikan
        # dengan sisa query memakai state=1.
        remaining = MAX_QUERIES - queries
        checkpoint = None

        for i, (a, b) in enumerate(history):
            if a <= b and ceil_log2(b - a + 1) + 1 <= remaining:
                checkpoint = (i, a, b)
                break

        if checkpoint is None:
            return

        idx, lo, hi = checkpoint
        print(f"[attempt {attempt}] fallback from checkpoint query {idx}, remaining={remaining}")

        # Phase 2: finish pakai state=1.
        while lo < hi and queries < MAX_QUERIES - 1:
            mid = (lo + hi) // 2
            ans = ask(sock, 1, mid)
            queries += 1

            if ans == "equal":
                return

            if ans == "smaller":
                lo = mid + 1
            elif ans == "larger":
                hi = mid - 1

        if lo == hi and queries < MAX_QUERIES:
            ask(sock, 1, lo)
            queries += 1

    finally:
        try:
            sock.close()
        except Exception:
            pass


def main():
    attempt = 1

    while True:
        try:
            print(f"[+] attempt {attempt}")
            run_once(attempt)
        except Found as e:
            print(f"\n[+] FLAG: {e.flag}")
            return
        except Exception as e:
            print(f"[-] attempt {attempt} failed: {e}")

        attempt += 1
        time.sleep(0.2)


if __name__ == "__main__":
    main()
