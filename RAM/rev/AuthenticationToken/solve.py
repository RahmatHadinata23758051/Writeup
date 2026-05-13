#!/usr/bin/env python3
import socket
import time
import argparse

PART1 = "OVERLORD"

def part2_from_ts(ts):
    target2 = (int(ts) >> 2).to_bytes(8, "little")
    return ''.join(chr((b % 26) + 0x61) for b in target2)

def p3_raw_ascii(a, b):
    return chr(((ord(a) + ord(b)) % 26) + 0x61)

def p3_alpha_upper(a, b):
    return chr((((ord(a) - ord('A')) + (ord(b) - ord('a'))) % 26) + ord('a'))

def p3_alpha_lower(a, b):
    return chr((((ord(a.lower()) - ord('a')) + (ord(b) - ord('a'))) % 26) + ord('a'))

def p3_mixed_sub_a(a, b):
    return chr(((ord(a) + ord(b) - ord('a')) % 26) + ord('a'))

FORMULAS = [
    ("raw_ascii", p3_raw_ascii),
    ("alpha_upper", p3_alpha_upper),
    ("alpha_lower", p3_alpha_lower),
    ("mixed_sub_a", p3_mixed_sub_a),
]

def gen_key(ts, formula):
    p2 = part2_from_ts(ts)
    p3 = ''.join(formula(a, b) for a, b in zip(PART1, p2))
    return ''.join(a + c + b for a, c, b in zip(PART1, p3, p2))

def try_key(host, port, key, timeout=2.0):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)

        out = b""
        try:
            out += s.recv(4096)
        except socket.timeout:
            pass

        s.sendall(key.encode() + b"\n")

        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                out += chunk
            except socket.timeout:
                break

        s.close()
        return out
    except Exception as e:
        return f"[socket error] {e}".encode()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="10.42.5.10")
    ap.add_argument("--port", type=int, default=1337)
    ap.add_argument("--window", type=int, default=86400)
    ap.add_argument("--timeout", type=float, default=1.0)
    args = ap.parse_args()

    now = int(time.time())
    seen = set()
    tried = 0

    offsets = []
    for delta in range(0, args.window + 1, 4):
        offsets.append(delta)
        if delta:
            offsets.append(-delta)

    for off in offsets:
        ts = now + off
        p2 = part2_from_ts(ts)

        for name, formula in FORMULAS:
            key = gen_key(ts, formula)
            if key in seen:
                continue
            seen.add(key)
            tried += 1

            print(f"[*] try={tried} off={off:+} p2={p2} formula={name} key={key}", flush=True)
            out = try_key(args.host, args.port, key, args.timeout)
            text = out.decode(errors="replace")
            print(text, flush=True)

            if "RMCTF{" in text or "FLAG:" in text:
                return

    print(f"[-] exhausted {tried} keys")

if __name__ == "__main__":
    main()
