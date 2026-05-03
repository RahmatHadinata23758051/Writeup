#!/usr/bin/env python3
import re
import subprocess
from pathlib import Path


PCAP = Path("chall.pcap")
RAW = Path("stream86.bin")
ZIP = Path("stream86_alt.bin")
OUTDIR = Path("solve_out")
PASSWORD = "IcyFl1pp3r$2026"


def run(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True)


def extract_stream() -> bytes:
    out = run(["tshark", "-r", str(PCAP), "-z", "follow,tcp,raw,86"])
    hex_chunks = re.findall(r"\b[0-9a-f]{20,}\b", out)
    data = bytes.fromhex("".join(hex_chunks))
    RAW.write_bytes(data)
    return data


def decode_zip(data: bytes) -> bytes:
    iv = data[4:20]
    body = data[24:]
    plain = bytes(b ^ iv[i % 16] for i, b in enumerate(body))
    ZIP.write_bytes(plain)
    return plain


def extract_files() -> None:
    if OUTDIR.exists():
        subprocess.run(["rm", "-rf", str(OUTDIR)], check=True)
    OUTDIR.mkdir()
    subprocess.run(
        ["7z", "x", "-y", f"-p{PASSWORD}", f"-o{OUTDIR}", str(ZIP)],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def main() -> None:
    data = extract_stream()
    decode_zip(data)
    extract_files()
    report = (OUTDIR / "mission_report.txt").read_text(encoding="utf-8")
    m = re.search(r"KubSTU\{[^}]+\}", report)
    if not m:
        raise SystemExit("Flag not found")
    print(m.group(0))


if __name__ == "__main__":
    main()
