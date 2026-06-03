#!/usr/bin/env python3
from pathlib import Path
import hashlib
import hmac
import re
import struct
import zlib

try:
    from Crypto.Cipher import AES as _PyCryptoAES
except ImportError:
    _PyCryptoAES = None

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    Cipher = algorithms = modes = None


def aes_ecb_encrypt_block(key: bytes, block: bytes) -> bytes:
    if _PyCryptoAES is not None:
        return _PyCryptoAES.new(key, _PyCryptoAES.MODE_ECB).encrypt(block)
    if Cipher is not None:
        encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        return encryptor.update(block) + encryptor.finalize()
    raise RuntimeError("Need pycryptodome or cryptography for AES")

PDF_PATH = Path("mistery.pdf")
ZIP_PATH = Path("flag.zip")


def extract_pdf_password(pdf_bytes: bytes) -> str:
    """Extract visible password hint from compressed PDF content streams."""
    candidates = []
    for m in re.finditer(rb"stream\r?\n", pdf_bytes):
        start = m.end()
        end = pdf_bytes.find(b"endstream", start)
        if end < 0:
            continue
        raw = pdf_bytes[start:end].strip(b"\r\n")
        for wbits in (15, -15):
            try:
                dec = zlib.decompress(raw, wbits)
            except Exception:
                continue
            candidates.append(dec)

    joined = b"\n".join(candidates)

    # The PDF text object stores characters as UTF-16BE-like bytes: \x00p\x00w\x00d...
    text = joined.replace(b"\x00", b"").decode("latin1", errors="ignore")
    m = re.search(r"pwd:([A-Za-z0-9_\-{}!?]+)", text)
    if not m:
        raise RuntimeError("Could not find pwd:<value> in PDF streams")
    return m.group(1)


def parse_aes_zip_member(zip_bytes: bytes, target_name: bytes = b"flag/flag.txt"):
    """Return metadata and encrypted blob for a WinZip AES-encrypted member."""
    cd = zip_bytes.find(b"PK\x01\x02")
    if cd < 0:
        raise RuntimeError("Central directory not found")

    off = cd
    selected = None
    while zip_bytes[off:off + 4] == b"PK\x01\x02":
        fields = struct.unpack_from("<4s6H3L5H2L", zip_bytes, off)
        (
            _sig, _vmade, _vneed, flag_bits, comp_method, _mtime, _mdate,
            crc32, comp_size, uncomp_size, name_len, extra_len, comment_len,
            _disk, _iattr, _eattr, local_off,
        ) = fields
        name = zip_bytes[off + 46:off + 46 + name_len]
        extra = zip_bytes[off + 46 + name_len:off + 46 + name_len + extra_len]
        if name == target_name:
            selected = (flag_bits, comp_method, crc32, comp_size, uncomp_size, local_off, extra)
            break
        off += 46 + name_len + extra_len + comment_len

    if selected is None:
        raise RuntimeError(f"Member {target_name!r} not found")

    flag_bits, comp_method, crc32, comp_size, uncomp_size, local_off, central_extra = selected
    if comp_method != 99:
        raise RuntimeError("Expected WinZip AES compression method 99")

    # Parse AES extra field: 0x9901, size 7: version, vendor, strength, actual compression method.
    strength = None
    actual_comp = None
    p = 0
    while p + 4 <= len(central_extra):
        header_id, size = struct.unpack_from("<HH", central_extra, p)
        val = central_extra[p + 4:p + 4 + size]
        if header_id == 0x9901:
            _ver, vendor, strength, actual_comp = struct.unpack("<H2sBH", val)
            if vendor != b"AE":
                raise RuntimeError("Unexpected AES vendor")
            break
        p += 4 + size
    if strength is None:
        raise RuntimeError("AES extra field not found")

    # Local header tells where encrypted AES payload starts.
    lf = struct.unpack_from("<4s5H3L2H", zip_bytes, local_off)
    sig, _ver, _lf_flag, _lf_comp, _mt, _md, _lf_crc, _lf_cs, _lf_us, name_len, extra_len = lf
    if sig != b"PK\x03\x04":
        raise RuntimeError("Bad local file header")
    data_off = local_off + 30 + name_len + extra_len
    enc_blob = zip_bytes[data_off:data_off + comp_size]
    return strength, actual_comp, crc32, uncomp_size, enc_blob


def decrypt_winzip_aes(password: bytes, strength: int, actual_comp: int, crc32: int, uncomp_size: int, enc_blob: bytes) -> bytes:
    key_len = {1: 16, 2: 24, 3: 32}[strength]
    salt_len = {1: 8, 2: 12, 3: 16}[strength]

    salt = enc_blob[:salt_len]
    pwd_verifier = enc_blob[salt_len:salt_len + 2]
    ciphertext = enc_blob[salt_len + 2:-10]
    auth_code = enc_blob[-10:]

    keymat = hashlib.pbkdf2_hmac("sha1", password, salt, 1000, 2 * key_len + 2)
    enc_key = keymat[:key_len]
    mac_key = keymat[key_len:2 * key_len]
    verifier = keymat[-2:]

    if verifier != pwd_verifier:
        raise RuntimeError("Bad password verifier")
    if hmac.new(mac_key, ciphertext, hashlib.sha1).digest()[:10] != auth_code:
        raise RuntimeError("Bad AES authentication code")

    # WinZip AES uses AES-CTR with little-endian counter blocks starting at 1.
    out = bytearray()
    for block_idx in range((len(ciphertext) + 15) // 16):
        counter = (block_idx + 1).to_bytes(16, "little")
        keystream = aes_ecb_encrypt_block(enc_key, counter)
        chunk = ciphertext[block_idx * 16:(block_idx + 1) * 16]
        out.extend(a ^ b for a, b in zip(chunk, keystream))

    compressed = bytes(out[:len(ciphertext)])
    if actual_comp == 8:
        plaintext = zlib.decompress(compressed, -15)
    elif actual_comp == 0:
        plaintext = compressed
    else:
        raise RuntimeError(f"Unsupported actual compression method: {actual_comp}")

    if len(plaintext) != uncomp_size:
        raise RuntimeError("Unexpected plaintext size")
    if (zlib.crc32(plaintext) & 0xffffffff) != crc32:
        raise RuntimeError("CRC mismatch")
    return plaintext


def main():
    pdf_bytes = PDF_PATH.read_bytes()
    zip_bytes = ZIP_PATH.read_bytes()

    visible_pwd = extract_pdf_password(pdf_bytes)
    # The visible PDF password is a hint; the actual ZIP password is its MD5 hex.
    zip_password = hashlib.md5(visible_pwd.encode()).hexdigest().encode()

    strength, actual_comp, crc32, uncomp_size, enc_blob = parse_aes_zip_member(zip_bytes)
    flag = decrypt_winzip_aes(zip_password, strength, actual_comp, crc32, uncomp_size, enc_blob)
    print(f"<FLAG>{flag.decode()}</FLAG>")


if __name__ == "__main__":
    main()
