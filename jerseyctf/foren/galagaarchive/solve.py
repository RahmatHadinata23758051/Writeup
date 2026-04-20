#!/usr/bin/env python3
import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

FLAG_RE = re.compile(r"jctf\{[^\n\r\t\x00}]+\}")


def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{p.stderr}")
    return p.stdout


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore").strip()


def xor_sha256_hex(hex_blob: str, password: str, offset: int = 0) -> bytes:
    key = hashlib.sha256(password.encode()).digest()
    data = bytes.fromhex(hex_blob.strip())
    return bytes(b ^ key[(i + offset) % 32] for i, b in enumerate(data))


def pick_file(base: Path, names):
    for n in names:
        p = base / n
        if p.exists():
            return p
    return None


def main():
    ap = argparse.ArgumentParser(description="Solve JerseyCTF Galaga Archive")
    ap.add_argument("pcap", nargs="?", default="galaga_galaxy_invaders2.pcap")
    args = ap.parse_args()

    pcap = Path(args.pcap)
    if not pcap.exists():
        print(f"[!] PCAP not found: {pcap}")
        sys.exit(1)

    if shutil.which("tshark") is None:
        print("[!] tshark not found. Install Wireshark/tshark first.")
        sys.exit(1)

    with tempfile.TemporaryDirectory(prefix="galaga_objs_") as td:
        outdir = Path(td)
        run(["tshark", "-r", str(pcap), "--export-objects", f"smb,{outdir}"])

        ideas1 = pick_file(outdir, ["%5cideas1.txt", "ideas1.txt", "\\ideas1.txt"])
        ideas2 = pick_file(outdir, ["%5cideas2.txt", "ideas2.txt", "\\ideas2.txt"])

        if not ideas1 or not ideas2:
            print("[!] ideas1.txt / ideas2.txt not found in SMB exported objects")
            sys.exit(1)

        # Recovered credential from AS-REP roast on user galatic
        password = "galagalogz"

        pt1 = xor_sha256_hex(read_text(ideas1), password, 0)
        if b"cool! here is my update" in pt1.lower():
            print("[+] Decrypted ideas1 successfully")
        else:
            print("[!] ideas1 plaintext check failed, continuing anyway")

        found = None
        for off in range(32):
            pt2 = xor_sha256_hex(read_text(ideas2), password, off)
            m = FLAG_RE.search(pt2.decode("utf-8", errors="ignore"))
            if m:
                found = m.group(0)
                break

        if not found:
            print("[!] Flag not found")
            sys.exit(2)

        print(found)


if __name__ == "__main__":
    main()
