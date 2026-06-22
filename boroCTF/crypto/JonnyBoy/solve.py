#!/usr/bin/env python3
import hashlib
import hmac
import re
import struct
import zlib
from pathlib import Path
from typing import Iterable

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ZIP_FILES = [
    Path('a_USE.zip'),
    Path('b_JOHN.zip'),
    Path('c_THE.zip'),
    Path('d_RIPPER.zip'),
]


def parse_wz_aes_zip(path: Path) -> dict:
    data = path.read_bytes()
    if data[:4] != b'PK\x03\x04':
        raise ValueError(f'{path}: not a local ZIP header')

    (
        version,
        flags,
        method,
        mtime,
        mdate,
        crc32,
        compressed_size,
        uncompressed_size,
        filename_len,
        extra_len,
    ) = struct.unpack_from('<HHHHHIIIHH', data, 4)

    filename = data[30:30 + filename_len].decode(errors='replace')
    extra = data[30 + filename_len:30 + filename_len + extra_len]
    payload_off = 30 + filename_len + extra_len
    payload = data[payload_off:payload_off + compressed_size]

    # WinZip AES extra field: 0x9901, 7 bytes:
    # version(2), vendor("AE"), strength(1), actual_compression_method(2)
    if method != 99 or b'AE' not in extra:
        raise ValueError(f'{path}: not WinZip AES method 99')

    strength = extra[8]
    actual_method = struct.unpack_from('<H', extra, 9)[0]
    salt_len = {1: 8, 2: 12, 3: 16}[strength]
    key_len = {1: 16, 2: 24, 3: 32}[strength]

    return {
        'archive': path.name,
        'filename': filename,
        'salt': payload[:salt_len],
        'password_verifier': payload[salt_len:salt_len + 2],
        'ciphertext': payload[salt_len + 2:-10],
        'auth_code': payload[-10:],
        'actual_method': actual_method,
        'key_len': key_len,
    }


def decrypt_entry(entry: dict, password: str) -> bytes | None:
    key_len = entry['key_len']
    derived = hashlib.pbkdf2_hmac(
        'sha1',
        password.encode(),
        entry['salt'],
        1000,
        2 * key_len + 2,
    )

    enc_key = derived[:key_len]
    mac_key = derived[key_len:2 * key_len]
    verifier = derived[-2:]

    if verifier != entry['password_verifier']:
        return None

    # The 2-byte verifier can collide. The truncated HMAC is the real check.
    expected_auth = hmac.new(mac_key, entry['ciphertext'], hashlib.sha1).digest()[:10]
    if expected_auth != entry['auth_code']:
        return None

    # WinZip AES uses AES-CTR with a little-endian counter starting at 1.
    cipher = Cipher(algorithms.AES(enc_key), modes.ECB()).encryptor()
    plaintext_compressed = bytearray()
    counter = 1
    ciphertext = entry['ciphertext']

    for off in range(0, len(ciphertext), 16):
        keystream = cipher.update(counter.to_bytes(16, 'little'))
        block = ciphertext[off:off + 16]
        plaintext_compressed.extend(a ^ b for a, b in zip(block, keystream))
        counter += 1

    raw = bytes(plaintext_compressed)
    if entry['actual_method'] == 8:      # deflate
        return zlib.decompress(raw, -15)
    if entry['actual_method'] == 0:      # stored
        return raw
    raise ValueError(f"unsupported compression method: {entry['actual_method']}")


def edits_around_chips() -> Iterable[str]:
    # The first cracked password was "chips". The final archive follows the same
    # base word with a tiny mutation: singular + punctuation.
    seeds = [
        'chips', 'chip', 'chip!', 'Chips', 'CHIPS', 'ch1ps', 'Ch1ps',
        'chips!', 'chip1', 'chip123', 'chips123', 'chips2026',
        'crisps', 'crisp', 'snack', 'snacks', 'fries', 'nachos',
    ]
    seen = set()
    for value in seeds:
        if value not in seen:
            seen.add(value)
            yield value


def main() -> None:
    entries = [parse_wz_aes_zip(path) for path in ZIP_FILES if path.exists()]
    candidates = list(edits_around_chips())
    flag = None

    for entry in entries:
        for password in candidates:
            plaintext = decrypt_entry(entry, password)
            if plaintext is None:
                continue

            print(f"[+] {entry['archive']}:{entry['filename']} password={password!r}")
            decoded = plaintext.decode(errors='replace')
            print(decoded)

            match = re.search(r'boroCTF\{[^}]+\}', decoded)
            if match:
                flag = match.group(0)
                print(f'<FLAG>{flag}</FLAG>')
                return

    if flag is None:
        raise SystemExit('flag not found with current candidate rules')


if __name__ == '__main__':
    main()
