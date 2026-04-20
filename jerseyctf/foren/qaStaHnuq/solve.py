#!/usr/bin/env python3
"""
CTF Solver: qaStaH nuq - JerseyCTF
Category: Forensics
Technique: PCAP analysis → HTTP payload → hex decode → base64 decode
"""

import subprocess
import binascii
import base64
import re

PCAP = "qaStaH_nuq.pcap"

# ─── Step 1: Extract HTTP file_data via tshark ────────────────────────────────
def extract_http_data(pcap):
    result = subprocess.run(
        ["tshark", "-r", pcap, "-Y", "http", "-T", "fields", "-e", "http.file_data"],
        capture_output=True, text=True
    )
    lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
    return lines

# ─── Step 2: Hex decode ───────────────────────────────────────────────────────
def hex_decode(s):
    return bytes.fromhex(s).decode()

# ─── Step 3: Base64 decode ────────────────────────────────────────────────────
def b64_decode(s):
    s += '=' * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s).decode()

# ─── Step 4: Find flag ────────────────────────────────────────────────────────
def find_flag(s):
    match = re.search(r'(flag\{[^}]+\}|jctf\{[^}]+\})', s)
    return match.group(1) if match else None

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print("=" * 55)
    print("  qaStaH nuq — PCAP Forensics Solver")
    print("=" * 55)

    # Step 1
    print(f"\n[1] Extracting HTTP payload from: {PCAP}")
    http_fields = extract_http_data(PCAP)
    if not http_fields:
        print("    [!] No HTTP data found. Is tshark installed?")
        print("    [!] Falling back to known value...")
        http_fields = ["616d4e305a6e744264485268593274665647686c583056756447567963484a7063325639"]

    raw_hex = http_fields[0]
    print(f"    Raw hex: {raw_hex}")

    # Step 2
    layer1 = hex_decode(raw_hex)
    print(f"\n[2] After hex decode:")
    print(f"    {layer1}")

    # Step 3
    layer2 = b64_decode(layer1)
    print(f"\n[3] After base64 decode:")
    print(f"    {layer2}")

    # Step 4
    flag = find_flag(layer2)

    print("\n" + "=" * 55)
    if flag:
        print(f"  FLAG: {flag}")
    else:
        print(f"  [!] Flag pattern not found. Full output: {layer2}")
    print("=" * 55)

if __name__ == "__main__":
    main()
