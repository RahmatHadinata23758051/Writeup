#!/usr/bin/env python3
from pathlib import Path
import base64
import lzma
import string

ARCHIVE = Path("chall.7z")
if not ARCHIVE.exists():
    ARCHIVE = Path("/mnt/data/chall.7z")

BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
BASE45_INDEX = {ch: i for i, ch in enumerate(BASE45_ALPHABET)}


def extract_challenge_files(archive_path: Path) -> tuple[bytes, bytes]:
    """Minimal extractor for this 7z: one LZMA stream containing key.enc + chall.enc."""
    data = archive_path.read_bytes()
    if not data.startswith(b"7z\xbc\xaf\x27\x1c"):
        raise ValueError("not a 7z archive")

    # These values are read from the decoded 7z header:
    # pack size      : 41055 bytes
    # unpacked size  : 124236 bytes
    # substream size : key.enc = 124020, chall.enc = 216
    packed_size = 41055
    key_size = 124020

    packed = data[0x20:0x20 + packed_size]
    filters = [{
        "id": lzma.FILTER_LZMA1,
        "dict_size": 0x800000,
        "lc": 3,
        "lp": 0,
        "pb": 2,
    }]
    unpacked = lzma.decompress(packed, format=lzma.FORMAT_RAW, filters=filters)

    key_enc = unpacked[:key_size]
    chall_enc = unpacked[key_size:]
    return key_enc, chall_enc


def base45_decode(text: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(text):
        if i + 2 < len(text):
            x = (
                BASE45_INDEX[text[i]]
                + BASE45_INDEX[text[i + 1]] * 45
                + BASE45_INDEX[text[i + 2]] * 45 * 45
            )
            out.extend([x // 256, x % 256])
            i += 3
        elif i + 1 < len(text):
            x = BASE45_INDEX[text[i]] + BASE45_INDEX[text[i + 1]] * 45
            out.append(x)
            i += 2
        else:
            raise ValueError("invalid Base45 length")
    return bytes(out)


def mostly_printable(data: bytes) -> bool:
    allowed = set(bytes(string.printable, "ascii"))
    return bool(data) and all(b in allowed for b in data)


def unwrap_key(key_enc: bytes) -> str:
    # key.enc: Base45, then a stack of Base64 layers.
    cur = base45_decode(key_enc.decode())

    while True:
        stripped = cur.strip()
        b64chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        if not stripped or any(c not in b64chars for c in stripped):
            break

        try:
            nxt = base64.b64decode(stripped + b"===")
        except Exception:
            break

        # Stop before the final visible key gets decoded into binary junk.
        if not mostly_printable(nxt):
            break
        cur = nxt

    return cur.decode().strip()


def base100_decode(encoded: bytes) -> bytes:
    # chall.enc is hex text of UTF-8 emojis. Base100 encodes one byte into:
    # f0 9f XX YY, with byte = (XX - 0x8f) * 64 + (YY - 0x80) - 55
    emoji_bytes = bytes.fromhex(encoded.decode().strip())
    if len(emoji_bytes) % 4 != 0:
        raise ValueError("invalid Base100 byte length")

    out = bytearray()
    for i in range(0, len(emoji_bytes), 4):
        a, b, c, d = emoji_bytes[i:i + 4]
        if (a, b) != (0xF0, 0x9F):
            raise ValueError("unexpected emoji UTF-8 prefix")
        out.append((c - 0x8F) * 64 + (d - 0x80) - 55)
    return bytes(out)


def beaufort_decrypt(ciphertext: str, key: str) -> str:
    # Beaufort: P = K - C (mod 26), key advances only on letters.
    out = []
    j = 0
    key = key.upper()

    for ch in ciphertext:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            c = ord(ch) - base
            k = ord(key[j % len(key)]) - ord("A")
            p = (k - c) % 26
            out.append(chr(base + p))
            j += 1
        else:
            out.append(ch)

    return "".join(out)


def main() -> None:
    key_enc, chall_enc = extract_challenge_files(ARCHIVE)
    key = unwrap_key(key_enc)
    intermediate = base100_decode(chall_enc).decode()
    flag = beaufort_decrypt(intermediate, key).strip()

    print(f"[+] key            : {key}")
    print(f"[+] after Base100  : {intermediate.strip()}")
    print(f"[+] flag           : {flag}")
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()

