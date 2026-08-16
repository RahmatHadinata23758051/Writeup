#!/usr/bin/env python3
"""Recover the SignalLost dispatch from the supplied bundle."""
from pathlib import Path
import base64
import re
import subprocess

ROOT = Path(__file__).resolve().parent
pdf = ROOT / "_e19a0c57-4c8f-4e2c-a113-5bf01af8e2dd.jpg"
carrier = ROOT / "_2bd3f369-46d0-4a60-9aa1-1f5d4e77d0fb.jpg"
stage2 = ROOT / "signal_stage2.bin"
out = ROOT / "solve_output"
out.mkdir(exist_ok=True)

pdf_text = out / "dispatch.txt"
subprocess.run(["pdftotext", "-upw", "trustno1", str(pdf), str(pdf_text)], check=True)
text = pdf_text.read_text()
encoded = re.search(r"([A-Za-z0-9+/]{20,}={0,2})", text).group(1)
key = encoded
for _ in range(3):
    key = base64.b64decode(key).decode()
print("archive key:", key)

raw = carrier.read_bytes()
eoi = raw.rfind(b"\xff\xd9") + 2
blob = raw[eoi:].decode()
payload = blob.split("BEGIN_SIGNAL_BLOB", 1)[1].split("END_SIGNAL_BLOB", 1)[0]
stage1 = base64.b64decode("".join(payload.split()))
stage2.write_bytes(bytes.fromhex(stage1.decode()))

subprocess.run(["7z", "x", "-y", f"-p{key}", str(stage2), f"-o{out}"], check=True)
for path in out.rglob("*"):
    if path.is_file():
        match = re.search(r"Thryve\{[^}]+\}", path.read_text(errors="ignore"))
        if match:
            print(match.group(0))
            break
