#!/usr/bin/env python3
import argparse
import base64
import hashlib
import re
import subprocess
import sys
from pathlib import Path

INITIAL_KEY = b"AIMIEJEGO40i4qwertyuiopazertyuio"


def run_tshark(pcap_path: str) -> list[str]:
    cmd = [
        "tshark",
        "-r",
        pcap_path,
        "-Y",
        'dns.qry.name contains "backup.site.lan"',
        "-T",
        "fields",
        "-e",
        "dns.qry.name",
    ]
    out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    return [line.strip() for line in out.splitlines() if line.strip()]


def parse_chunks(dns_names: list[str]) -> list[tuple[int, bytes]]:
    # Format:
    # <md5>.<seq>.<hex-part1>.<hex-part2>.backup.site.lan
    pat = re.compile(
        r"^(?P<id>[0-9a-f]{32})\.(?P<seq>\d+)\.(?P<h1>[0-9a-f]+)\.(?P<h2>[0-9a-f]+)\.backup\.site\.lan$"
    )
    chunks: dict[int, bytes] = {}

    for q in dns_names:
        m = pat.match(q)
        if not m:
            continue
        seq = int(m.group("seq"))
        enc_hex = m.group("h1") + m.group("h2")
        chunks[seq] = bytes.fromhex(enc_hex)

    if not chunks:
        raise RuntimeError("No DNS exfil chunks found.")

    missing = [i for i in range(min(chunks), max(chunks) + 1) if i not in chunks]
    if missing:
        raise RuntimeError(f"Missing chunk indexes: {missing}")

    return sorted(chunks.items())


def decrypt_payload(chunks: list[tuple[int, bytes]]) -> bytes:
    key = INITIAL_KEY
    out = bytearray()

    for _, enc in chunks:
        dec = bytes([b ^ k for b, k in zip(enc, key[: len(enc)])])
        out.extend(dec)
        key = hashlib.md5(dec + key).hexdigest().encode("utf-8")

    return bytes(out)


def caesar_minus_one(s: str, shift_digits: bool = False) -> str:
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") - 1) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") - 1) % 26 + ord("A")))
        elif shift_digits and "0" <= ch <= "9":
            out.append(chr((ord(ch) - ord("0") - 1) % 10 + ord("0")))
        else:
            out.append(ch)
    return "".join(out)


def extract_flag(payload: bytes) -> str:
    lines = [ln.strip() for ln in payload.decode("utf-8", errors="ignore").splitlines() if ln.strip()]

    decoded_lines = []
    for ln in lines:
        try:
            decoded_lines.append(base64.b64decode(ln).decode("utf-8", errors="ignore"))
        except Exception:
            pass

    for line in decoded_lines:
        plain = caesar_minus_one(line, shift_digits=True)
        m = re.search(r"putcCTF\{[^}]+\}", plain)
        if m:
            return m.group(0)

    raise RuntimeError("Flag not found in decoded payload.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve Help me forensic challenge")
    parser.add_argument("pcap", nargs="?", default="incident-v3.pcapng", help="Path to pcapng file")
    args = parser.parse_args()

    pcap = Path(args.pcap)
    if not pcap.exists():
        print(f"[-] File not found: {pcap}", file=sys.stderr)
        return 1

    dns_names = run_tshark(str(pcap))
    chunks = parse_chunks(dns_names)
    payload = decrypt_payload(chunks)
    flag = extract_flag(payload)

    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
