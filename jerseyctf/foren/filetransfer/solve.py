#!/usr/bin/env python3
import re
import subprocess
import sys
from pathlib import Path

KEY = b"sorry_im_not_the_flag_:)"


def run_tshark_extract(pcap_path: str):
    cmd = [
        "tshark",
        "-r",
        pcap_path,
        "-Y",
        "tcp.stream==0 && ip.src==10.1.2.211 && tcp.len>0",
        "-T",
        "fields",
        "-e",
        "data",
    ]
    out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    return [line.strip() for line in out.splitlines() if line.strip()]


def xor_decode(hex_blob: str) -> str:
    raw = bytes.fromhex(hex_blob)
    decoded = bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(raw))
    return decoded.decode("latin1", errors="ignore")


def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else "export.pcap"
    if not Path(pcap).exists():
        print(f"[-] File tidak ditemukan: {pcap}")
        return 1

    try:
        blobs = run_tshark_extract(pcap)
    except Exception as e:
        print(f"[-] Gagal ekstrak data dari tshark: {e}")
        return 1

    if not blobs:
        print("[-] Tidak ada payload yang cocok di stream C2")
        return 1

    decoded_msgs = [xor_decode(b) for b in blobs]

    flag = None
    for msg in decoded_msgs:
        m = re.search(r"jctf\{[^}]+\}", msg)
        if m:
            flag = m.group(0)
            break

    if not flag:
        print("[-] Flag tidak ditemukan")
        print("\n[DEBUG] Decoded messages:")
        for i, m in enumerate(decoded_msgs, 1):
            print(f"{i}. {m}")
        return 1

    print(f"<FLAG>{flag}</FLAG>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
