#!/usr/bin/env python3
from __future__ import annotations

import binascii
import hashlib
import io
import lzma
import re
import shutil
import subprocess
import sys
from pathlib import Path

ARCHIVE_NAME = "China_Crack_01.7z"
ZIP_PASSWORD = "D4mn_br0_H0n3y_p07_7yp3_5h1d"
DERIVED_SM2_KEY = (ZIP_PASSWORD + "_V1T").encode()

# Constants parsed from the 7z header after the password was verified.
MAIN_PACK_OFFSET = 32
MAIN_PACK_SIZE = 21456
AES_OUTPUT_SIZE = 21446
LZMA2_DICT_SIZE = 49152
UNPACKED_SIZE = 40184
MAIN_AES_IV = bytes.fromhex("27fec4691b7a387315d5612988b49e32")
KDF_CYCLES = 1 << 19

# SM2 recommended curve over Fp (same parameters used by the Chinese SM2 standard).
P = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
A = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
B = int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
N = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)


def sm3_fallback(data: bytes) -> bytes:
    """Small pure-Python SM3 implementation used if OpenSSL/hashlib has no SM3."""
    def rotl(x: int, n: int) -> int:
        n &= 31
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def p0(x: int) -> int:
        return x ^ rotl(x, 9) ^ rotl(x, 17)

    def p1(x: int) -> int:
        return x ^ rotl(x, 15) ^ rotl(x, 23)

    def ff(x: int, y: int, z: int, j: int) -> int:
        return x ^ y ^ z if j <= 15 else ((x & y) | (x & z) | (y & z))

    def gg(x: int, y: int, z: int, j: int) -> int:
        return x ^ y ^ z if j <= 15 else ((x & y) | ((~x) & z))

    iv = [
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
    ]
    bit_len = len(data) * 8
    msg = bytearray(data) + b"\x80"
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += bit_len.to_bytes(8, "big")

    v = iv[:]
    for off in range(0, len(msg), 64):
        block = msg[off:off + 64]
        w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
        for j in range(16, 68):
            w.append((p1(w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15)) ^ rotl(w[j - 13], 7) ^ w[j - 6]) & 0xFFFFFFFF)
        w1 = [(w[j] ^ w[j + 4]) & 0xFFFFFFFF for j in range(64)]
        a, b, c, d, e, f, g, h = v
        for j in range(64):
            tj = 0x79CC4519 if j <= 15 else 0x7A879D8A
            ss1 = rotl((rotl(a, 12) + e + rotl(tj, j)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ rotl(a, 12)
            tt1 = (ff(a, b, c, j) + d + ss2 + w1[j]) & 0xFFFFFFFF
            tt2 = (gg(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
            d = c
            c = rotl(b, 9)
            b = a
            a = tt1
            h = g
            g = rotl(f, 19)
            f = e
            e = p0(tt2)
        v = [x ^ y for x, y in zip(v, [a, b, c, d, e, f, g, h])]
    return b"".join(x.to_bytes(4, "big") for x in v)


def sm3(data: bytes) -> bytes:
    try:
        h = hashlib.new("sm3")
        h.update(data)
        return h.digest()
    except Exception:
        return sm3_fallback(data)


def sevenz_kdf(password: str) -> bytes:
    h = hashlib.sha256()
    pw = password.encode("utf-16le")
    for counter in range(KDF_CYCLES):
        h.update(pw)
        h.update(counter.to_bytes(8, "little"))
    return h.digest()


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    try:
        from Crypto.Cipher import AES  # type: ignore
        return AES.new(key, AES.MODE_CBC, iv).decrypt(data)
    except Exception:
        pass

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return decryptor.update(data) + decryptor.finalize()
    except Exception:
        pass

    openssl = shutil.which("openssl")
    if openssl:
        p = subprocess.run(
            [openssl, "enc", "-aes-256-cbc", "-d", "-K", key.hex(), "-iv", iv.hex(), "-nopad"],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return p.stdout

    raise RuntimeError("Need pycryptodome, cryptography, or openssl for AES-CBC")


def inv_mod(x: int) -> int:
    return pow(x % P, P - 2, P)


def ec_add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = ((3 * x1 * x1 + A) * inv_mod(2 * y1)) % P
    else:
        lam = ((y2 - y1) * inv_mod(x2 - x1)) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def ec_mul(k: int, point: tuple[int, int]) -> tuple[int, int]:
    result = None
    addend = point
    while k:
        if k & 1:
            result = ec_add(result, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    if result is None:
        raise RuntimeError("Invalid EC multiplication result")
    return result


def sm2_kdf(z: bytes, klen: int) -> bytes:
    out = bytearray()
    ct = 1
    while len(out) < klen:
        out += sm3(z + ct.to_bytes(4, "big"))
        ct += 1
    return bytes(out[:klen])


def decrypt_archive(archive_path: Path) -> tuple[bytes, bytes, bytes]:
    blob = archive_path.read_bytes()
    pack = blob[MAIN_PACK_OFFSET:MAIN_PACK_OFFSET + MAIN_PACK_SIZE]
    key = sevenz_kdf(ZIP_PASSWORD)
    aes_plain = aes_cbc_decrypt(key, MAIN_AES_IV, pack)[:AES_OUTPUT_SIZE]
    folder_data = lzma.LZMADecompressor(
        format=lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA2, "dict_size": LZMA2_DICT_SIZE}],
    ).decompress(aes_plain, max_length=UNPACKED_SIZE)
    if len(folder_data) != UNPACKED_SIZE:
        raise RuntimeError(f"Unexpected unpacked size: {len(folder_data)}")
    if (binascii.crc32(folder_data) & 0xFFFFFFFF) != 0x44040664:
        raise RuntimeError("CRC check failed for extracted 7z payload")

    secret_bits = folder_data[:80].decode()
    secret = bytes(int(secret_bits[i:i + 8], 2) for i in range(0, len(secret_bits), 8))
    challenge = bytes.fromhex(folder_data[80:].decode())
    return secret, challenge, folder_data


def sm2_decrypt(ciphertext: bytes, private_key_bytes: bytes) -> bytes:
    if len(ciphertext) < 96:
        raise ValueError("SM2 ciphertext too short")
    c1 = (int.from_bytes(ciphertext[:32], "big"), int.from_bytes(ciphertext[32:64], "big"))
    if (c1[1] * c1[1] - (c1[0] ** 3 + A * c1[0] + B)) % P != 0:
        raise RuntimeError("C1 is not on the SM2 curve")

    c2 = ciphertext[64:-32]       # C1 || C2 || C3 layout
    c3 = ciphertext[-32:]
    d = int.from_bytes(private_key_bytes, "big") % N
    x2, y2 = ec_mul(d, c1)
    x2b = x2.to_bytes(32, "big")
    y2b = y2.to_bytes(32, "big")
    stream = sm2_kdf(x2b + y2b, len(c2))
    plaintext = bytes(a ^ b for a, b in zip(c2, stream))
    if sm3(x2b + plaintext + y2b) != c3:
        raise RuntimeError("SM2 C3 hash check failed")
    return plaintext


def try_ocr_png(png_bytes: bytes) -> str | None:
    """Optional convenience: read the rendered template if PIL + tesseract exist."""
    try:
        import pytesseract  # type: ignore
        from PIL import Image  # type: ignore
        img = Image.open(io.BytesIO(png_bytes))
        # Crop around the actual rendered flag line and enlarge it for OCR.
        crop = img.crop((250, 220, 850, 310)).resize((2400, 360))
        text = pytesseract.image_to_string(crop, config="--psm 7").strip()
        m = re.search(r"V1T\{[^}]+\}", text)
        return m.group(0) if m else None
    except Exception:
        return None


def main() -> None:
    archive_path = Path(sys.argv[1]) if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else Path(ARCHIVE_NAME)
    save_png = "--save-png" in sys.argv

    secret, challenge, _ = decrypt_archive(archive_path)
    if secret != b"sqrt(SMSM)":
        raise RuntimeError(f"Unexpected secret hint: {secret!r}")

    sm2_plain_hex = sm2_decrypt(challenge, DERIVED_SM2_KEY)
    png_bytes = bytes.fromhex(sm2_plain_hex.decode())
    if not png_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        raise RuntimeError("SM2 plaintext is not a PNG hex string")

    if save_png:
        Path("recovered_flag.png").write_bytes(png_bytes)

    template = try_ocr_png(png_bytes) or "V1T{Tryna_cRacK_iS_BaCk_MtfK_[that-zip-password-in-md5]}"
    md5_pw = hashlib.md5(ZIP_PASSWORD.encode()).hexdigest()
    flag = template.replace("[that-zip-password-in-md5]", md5_pw)
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
                              
