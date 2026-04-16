#!/usr/bin/env python3
import base64
import codecs
import io
import json
import os
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path

import requests

BASE_DIR = Path(__file__).resolve().parent
CHALL = BASE_DIR / "chall.txt"
TARGET = "https://rick-roll-0k02.onrender.com/x7a9kq"


def extract_zip_entries(chall_path: Path):
    with zipfile.ZipFile(chall_path, "r") as zf:
        files = {name: zf.read(name) for name in zf.namelist() if not name.endswith("/")}
    return files


def get_img_key(header_text: str) -> str:
    m = re.search(r'#define\s+IMG_KEY\s+"([^"]+)"', header_text)
    if not m:
        raise RuntimeError("IMG_KEY not found")
    return m.group(1)


def get_haha_value(header_text: str) -> int:
    m = re.search(r"#define\s+haha\s+(\d+)", header_text)
    if not m:
        raise RuntimeError("haha constant not found")
    return int(m.group(1))


def get_prepended_text(chall_bytes: bytes) -> str:
    pk = chall_bytes.find(b"PK\x03\x04")
    if pk == -1:
        raise RuntimeError("zip header not found")
    pre = chall_bytes[:pk]
    return pre.decode("latin-1", errors="ignore")


def decode_tinyurl_from_obf(pre_text: str, haha: int) -> str:
    pattern = re.compile(r"\(char\)\(haha \* haha\s*([+-])\s*(\d+)\)")
    ops = pattern.findall(pre_text)
    if not ops:
        raise RuntimeError("obfuscated char sequence not found")
    out = []
    base = haha * haha
    for sign, num in ops:
        n = int(num)
        v = base + n if sign == "+" else base - n
        out.append(chr(v))
    return "".join(out)


def steghide_extract(img_bytes: bytes, passphrase: str) -> bytes:
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        img = td / "i.jpg"
        out = td / "payload.bin"
        img.write_bytes(img_bytes)

        cmd = [
            "steghide",
            "extract",
            "-sf",
            str(img),
            "-p",
            passphrase,
            "-xf",
            str(out),
            "-f",
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"steghide extract failed:\n{proc.stdout}")
        return out.read_bytes()


def caesar_unshift(s: str, shift: int = 17) -> str:
    out = []
    for c in s:
        if "A" <= c <= "Z":
            out.append(chr((ord(c) - ord("A") - shift) % 26 + ord("A")))
        elif "a" <= c <= "z":
            out.append(chr((ord(c) - ord("a") - shift) % 26 + ord("a")))
        else:
            out.append(c)
    return "".join(out)


def decode_part2(hex_s: str) -> str:
    raw = bytes.fromhex(hex_s)
    key = b"secret"
    x = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    return base64.b64decode(x).decode()


def decode_part3(s: str) -> str:
    return codecs.decode(s, "rot_13")[::-1]


def main():
    chall_bytes = CHALL.read_bytes()
    zfiles = extract_zip_entries(CHALL)

    a = zfiles["x/a"].decode()
    b = zfiles["x/b"].decode()
    c = zfiles["x/c"].decode()
    header = a + "\n" + b + "\n" + c

    img_key = get_img_key(header)
    haha = get_haha_value(header)
    pre_text = get_prepended_text(chall_bytes)
    tiny = decode_tinyurl_from_obf(pre_text, haha)

    res = requests.post(TARGET, json={"input": tiny}, timeout=20)
    res.raise_for_status()
    data = res.json()
    if data.get("status") != "correct":
        raise RuntimeError(f"unexpected status: {data}")

    # Force stego extraction step as intended by challenge flow.
    _jar_bytes = steghide_extract(zfiles["x/i"], img_key)

    p1, p2, p3 = data["parts"]
    flag = caesar_unshift(p1) + decode_part2(p2) + decode_part3(p3)
    m = re.search(r"IIITL\{[^}]+\}", flag)
    if not m:
        raise RuntimeError(f"flag pattern not found in: {flag}")
    print(m.group(0))


if __name__ == "__main__":
    main()
