#!/usr/bin/env python3
"""
CTF Solver: Space Man - JerseyCTF
Category: Forensics / Steganography
Technique: LSB steganography (zsteg) → Vigenere cipher decryption
Key: 'gemini' (Project Gemini — paved the way to the Moon)
"""

import subprocess
import re

IMAGE = "space_man.png"

# ─── Step 1: Extract LSB data via zsteg ───────────────────────────────────────
def extract_lsb(image):
    result = subprocess.run(
        ["zsteg", image],
        capture_output=True, text=True
    )
    # Look for text pattern in b1,rgb,lsb,xy channel
    for line in result.stdout.splitlines():
        if "b1,rgb,lsb,xy" in line and "text:" in line:
            match = re.search(r'"([^"]+)"', line)
            if match:
                return match.group(1)
    return None

# ─── Step 2: Vigenere Decrypt ─────────────────────────────────────────────────
def vigenere_decrypt(ciphertext, key):
    key_chars = [c for c in key.lower() if c.isalpha()]
    result = ''
    ki = 0
    for c in ciphertext:
        if c.isalpha():
            shift = ord(key_chars[ki % len(key_chars)]) - ord('a')
            base  = ord('a') if c.islower() else ord('A')
            result += chr((ord(c) - base - shift) % 26 + base)
            ki += 1
        else:
            result += c
    return result

# ─── Step 3: Brute-force key (optional fallback) ──────────────────────────────
def brute_vigenere(ciphertext):
    candidates = [
        'gemini', 'gemini8', 'apollo', 'mercury', 'vostok',
        'saturn', 'armstrong', 'neil', 'moon', 'nasa',
        'projectgemini', 'projectapollo', 'projectmercury',
    ]
    for key in candidates:
        result = vigenere_decrypt(ciphertext, key)
        if result.startswith('flag{') or result.startswith('jctf{'):
            return result, key
    return None, None

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print("=" * 55)
    print("  Space Man — Steganography + Vigenere Solver")
    print("=" * 55)

    # Step 1: Extract LSB
    print(f"\n[1] Extracting LSB data from: {IMAGE}")
    encoded = extract_lsb(IMAGE)

    if not encoded:
        print("    [!] zsteg failed or not installed. Using known value...")
        encoded = "pgfn{jm_ilawfm_zs_sw_gw_zlq_ubwt}"

    print(f"    Extracted: {encoded}")

    # Step 2: Decrypt with known key
    KEY = "gemini"
    print(f"\n[2] Vigenere decrypt with key: '{KEY}'")
    flag = vigenere_decrypt(encoded, KEY)
    print(f"    Decrypted: {flag}")

    # Verify
    if not (flag.startswith('flag{') or flag.startswith('jctf{')):
        print("\n[!] Known key failed — brute forcing...")
        flag, KEY = brute_vigenere(encoded)
        if flag:
            print(f"    Found with key='{KEY}': {flag}")
        else:
            print("    [!] Brute force failed. Try more keys.")
            return

    print("\n" + "=" * 55)
    print(f"  FLAG: {flag}")
    print("=" * 55)

if __name__ == "__main__":
    main()
