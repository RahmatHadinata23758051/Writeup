#!/usr/bin/env python3
from pathlib import Path
import re
import subprocess
import sys

FW_PATH = Path(__file__).with_name("harald-blatann.hex")

# Dari disassembly callback write custom GATT characteristic:
# psa_cipher_decrypt(key_id, 0x04400040, 0x01028103, 0x60, out, 0x60, &out_len)
# Key di-import dari 0x01028163 sepanjang 0x20 byte.
CIPHERTEXT_ADDR = 0x01028103
CIPHERTEXT_LEN = 0x60
KEY_ADDR = 0x01028163
KEY_LEN = 0x20


def parse_intel_hex(path: Path) -> dict[int, int]:
    mem: dict[int, int] = {}
    upper = 0

    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line:
            continue
        if not line.startswith(":"):
            raise ValueError(f"bad Intel HEX line: {line!r}")

        size = int(line[1:3], 16)
        offset = int(line[3:7], 16)
        rectype = int(line[7:9], 16)
        data = bytes.fromhex(line[9:9 + size * 2])

        if rectype == 0x00:  # data
            base = upper + offset
            for i, b in enumerate(data):
                mem[base + i] = b
        elif rectype == 0x04:  # extended linear address
            upper = int.from_bytes(data, "big") << 16
        elif rectype == 0x01:  # EOF
            break

    return mem


def read_mem(mem: dict[int, int], addr: int, size: int) -> bytes:
    try:
        return bytes(mem[addr + i] for i in range(size))
    except KeyError as exc:
        missing = exc.args[0]
        raise KeyError(f"missing byte at firmware address 0x{missing:08x}") from None


def aes256_cbc_decrypt_raw(key: bytes, iv: bytes, data: bytes) -> bytes:
    # Prefer library lokal kalau ada. Fallback ke openssl CLI biar script tetap gampang jalan.
    try:
        from Crypto.Cipher import AES  # type: ignore
        return AES.new(key, AES.MODE_CBC, iv).decrypt(data)
    except Exception:
        pass

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return dec.update(data) + dec.finalize()
    except Exception:
        pass

    try:
        proc = subprocess.run(
            [
                "openssl", "enc", "-d", "-aes-256-cbc",
                "-K", key.hex(), "-iv", iv.hex(), "-nopad",
            ],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return proc.stdout
    except Exception as exc:
        raise RuntimeError(
            "Butuh PyCryptodome, cryptography, atau openssl untuk AES-CBC decrypt"
        ) from exc


def main() -> None:
    if not FW_PATH.exists():
        print(f"file firmware tidak ketemu: {FW_PATH}", file=sys.stderr)
        sys.exit(1)

    mem = parse_intel_hex(FW_PATH)
    blob = read_mem(mem, CIPHERTEXT_ADDR, CIPHERTEXT_LEN)
    key = read_mem(mem, KEY_ADDR, KEY_LEN)

    iv = blob[:16]
    ciphertext = blob[16:]
    plaintext = aes256_cbc_decrypt_raw(key, iv, ciphertext)

    match = re.search(rb"NNS\{[^}\r\n]+\}", plaintext)
    if not match:
        print("flag tidak ketemu di plaintext", file=sys.stderr)
        print(plaintext.hex(), file=sys.stderr)
        sys.exit(1)

    flag = match.group(0).decode()

    # Firmware cuma menganggap true kalau input > 0x3c byte dan prefix input sama
    # dengan plaintext hasil decrypt. Flag ini 61 byte, jadi pas dengan syarat itu.
    assert len(flag) > 0x3C
    assert plaintext.startswith(flag.encode())

    print(flag)
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
