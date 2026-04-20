#!/usr/bin/env python3
"""
CTF Solver: Recovered Signal File - JerseyCTF
Category: Forensics
Technique: Base64 decode + Caesar cipher (ROT-3) brute force
"""

import base64

# ─── Input ────────────────────────────────────────────────────────────────────
enc = "aW9kant2ZHdob29sd2hfdmxqcWRvX2doZnJnaGd9"

# ─── Step 1: Base64 Decode ────────────────────────────────────────────────────
def base64_decode(s):
    # Pad if needed
    s += '=' * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s).decode()

# ─── Step 2: ROT-N Brute Force ────────────────────────────────────────────────
def rot(s, n):
    result = ''
    for c in s:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            result += chr((ord(c) - base + n) % 26 + base)
        else:
            result += c
    return result

def brute_rot(s, markers=('flag{', 'jctf{')):
    for n in range(1, 26):
        candidate = rot(s, n)
        if any(m in candidate for m in markers):
            return candidate, n
    return None, None

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print("=" * 50)
    print("  Recovered Signal File — CTF Solver")
    print("=" * 50)

    print(f"\n[1] Encoded transmission:")
    print(f"    {enc}")

    # Step 1
    b64 = base64_decode(enc)
    print(f"\n[2] After Base64 decode:")
    print(f"    {b64}")

    # Step 2
    flag, shift = brute_rot(b64)
    if flag:
        print(f"\n[3] After ROT+{shift} (Caesar cipher):")
        print(f"    {flag}")
    else:
        print("\n[3] ROT brute force failed")

    print("\n" + "=" * 50)
    print(f"  FLAG: {flag}")
    print("=" * 50)

if __name__ == "__main__":
    main()
