#!/usr/bin/env python3
import argparse
import base64
import re
import sys
import zipfile
from pathlib import Path


DEFAULT_KEY = b"ThisIsA32ByteKeyForAES256!!12345"
DEFAULT_B64_OFFSET = 0x163
DEFAULT_B64_LEN = 44


def aes256_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    try:
        from Crypto.Cipher import AES  # type: ignore

        return AES.new(key, AES.MODE_ECB).decrypt(ciphertext)
    except Exception:
        import subprocess

        p = subprocess.run(
            ["openssl", "enc", "-d", "-aes-256-ecb", "-K", key.hex(), "-nopad"],
            input=ciphertext,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if p.returncode != 0:
            raise RuntimeError(p.stderr.decode(errors="ignore").strip())
        return p.stdout


def read_hidden_b64_from_mbr(vhd_path: Path) -> str:
    with vhd_path.open("rb") as f:
        mbr = f.read(512)

    if len(mbr) < 512:
        raise RuntimeError("Failed to read 512-byte MBR sector.")

    candidate = mbr[DEFAULT_B64_OFFSET : DEFAULT_B64_OFFSET + DEFAULT_B64_LEN].decode(
        "ascii", errors="ignore"
    )
    if re.fullmatch(r"[A-Za-z0-9+/=]{20,}", candidate):
        return candidate

    m = re.search(rb"([A-Za-z0-9+/]{20,}={0,2})", mbr)
    if not m:
        raise RuntimeError("No base64-like blob found in MBR.")
    return m.group(1).decode()


def read_key_from_zip(key_zip: Path, password: str) -> bytes:
    with zipfile.ZipFile(key_zip, "r") as zf:
        names = zf.namelist()
        if not names:
            raise RuntimeError("key.zip has no entries.")
        raw = zf.read(names[0], pwd=password.encode())
    return raw.strip()


def main() -> int:
    ap = argparse.ArgumentParser(description="Dead OS solver")
    ap.add_argument("--vhd", default="Dead_OS.vhd", help="Path to Dead_OS.vhd")
    ap.add_argument(
        "--key-zip",
        default="key.zip",
        help="Path to key.zip (optional, used with --zip-password)",
    )
    ap.add_argument(
        "--zip-password",
        default=None,
        help="Password for key.zip (example: Passw0rd123)",
    )
    args = ap.parse_args()

    vhd_path = Path(args.vhd)
    if not vhd_path.exists():
        print(f"[!] Missing VHD: {vhd_path}", file=sys.stderr)
        return 1

    key = DEFAULT_KEY
    if args.zip_password is not None:
        key_zip = Path(args.key_zip)
        if not key_zip.exists():
            print(f"[!] Missing key zip: {key_zip}", file=sys.stderr)
            return 1
        key = read_key_from_zip(key_zip, args.zip_password)[:32]

    if len(key) != 32:
        print(f"[!] Key length must be 32, got {len(key)}", file=sys.stderr)
        return 1

    b64_blob = read_hidden_b64_from_mbr(vhd_path)
    ciphertext = base64.b64decode(b64_blob)
    plaintext = aes256_ecb_decrypt(ciphertext, key)
    decoded = plaintext.decode("utf-8", errors="ignore")
    flag = "".join(ch for ch in decoded if ch.isprintable())

    print(flag)
    if not flag.startswith("IIITL{"):
        print("[!] Decryption done, but result does not look like a flag.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
