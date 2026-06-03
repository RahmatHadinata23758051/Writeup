#!/usr/bin/env python3
import re
import subprocess
import sys
from pathlib import Path

from Crypto.Cipher import AES


PCAP_PATH = Path("sst_north_sector.pcap")
VAULT_PATH = Path("vault.img")
DECRYPTED_PATH = Path("vault.dec")
FLAG_OUT = Path("flag.txt")


def run(cmd, *, input_text=None):
    result = subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout


def extract_passphrase():
    pcap_bytes = PCAP_PATH.read_bytes()
    match = re.search(rb'"key": "vault_key", "value": "([^"]+)"', pcap_bytes)
    if not match:
        raise RuntimeError("vault_key not found in pcap")
    return match.group(1).decode()


def extract_volume_key(passphrase):
    output = run(
        [
            "cryptsetup",
            "luksDump",
            "--dump-volume-key",
            "--key-file",
            "-",
            str(VAULT_PATH),
        ],
        input_text=passphrase,
    )
    match = re.search(r"MK dump:\s*([0-9a-f \n\t]+)", output, re.IGNORECASE)
    if not match:
        raise RuntimeError("failed to extract volume key")
    hex_key = re.sub(r"[^0-9a-f]", "", match.group(1), flags=re.IGNORECASE)
    return bytes.fromhex(hex_key)


def mul_alpha(tweak):
    tweak = bytearray(tweak)
    carry = 0
    for i in range(16):
        new_carry = (tweak[i] >> 7) & 1
        tweak[i] = ((tweak[i] << 1) & 0xFF) | carry
        carry = new_carry
    if carry:
        tweak[0] ^= 0x87
    return bytes(tweak)


def decrypt_sector(aes_data, aes_tweak, sector_num, data):
    tweak = aes_tweak.encrypt(sector_num.to_bytes(16, "little"))
    out = bytearray(len(data))
    pos = 0
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        xored = bytes(a ^ b for a, b in zip(block, tweak))
        plain = aes_data.decrypt(xored)
        out[pos:pos + 16] = bytes(a ^ b for a, b in zip(plain, tweak))
        pos += 16
        tweak = mul_alpha(tweak)
    return bytes(out)


def decrypt_vault(volume_key):
    key1, key2 = volume_key[:32], volume_key[32:]
    aes_data = AES.new(key1, AES.MODE_ECB)
    aes_tweak = AES.new(key2, AES.MODE_ECB)

    payload_offset = 16 * 1024 * 1024
    sector_size = 512

    with VAULT_PATH.open("rb") as src, DECRYPTED_PATH.open("wb") as dst:
        src.seek(payload_offset)
        sector = 0
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            if len(chunk) % sector_size:
                raise RuntimeError("ciphertext payload is not sector aligned")
            out = bytearray()
            for off in range(0, len(chunk), sector_size):
                out.extend(
                    decrypt_sector(
                        aes_data,
                        aes_tweak,
                        sector,
                        chunk[off:off + sector_size],
                    )
                )
                sector += 1
            dst.write(out)


def extract_flag():
    flag = run(["icat", str(DECRYPTED_PATH), "15"]).strip()
    FLAG_OUT.write_text(flag + "\n")
    return flag


def main():
    if not PCAP_PATH.exists() or not VAULT_PATH.exists():
        raise SystemExit("expected sst_north_sector.pcap and vault.img in current directory")

    passphrase = extract_passphrase()
    volume_key = extract_volume_key(passphrase)
    decrypt_vault(volume_key)
    flag = extract_flag()
    print(flag)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(exc.stderr)
        raise
