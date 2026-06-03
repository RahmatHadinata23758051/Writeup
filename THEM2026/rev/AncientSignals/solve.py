#!/usr/bin/env python3
from pathlib import Path


BASE = 0x140001000
TEXT_FILE_OFFSET = 0x400
CHECK_FUNC = 0x1400032D0
CHECK_FUNC_END = 0x140003320
ENC_FLAG_VA = 0x140080000
ENC_FLAG_LEN = 0x37


def va_to_file_offset(va: int) -> int:
    return TEXT_FILE_OFFSET + (va - BASE)


def fnv1a_32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x1000193) & 0xFFFFFFFF
    return h


def lcg_stream(start: int, mult: int, inc: int, n: int) -> bytes:
    x = start
    out = bytearray()
    for _ in range(n):
        x = (x * mult + inc) & 0xFF
        out.append(x)
    return bytes(out)


def find_alignment(cipher_prefix: bytes, target: bytes = b"RIFF") -> tuple[int, int, int]:
    wanted = bytes(a ^ b for a, b in zip(cipher_prefix, target))
    for start in range(256):
        for mult in range(256):
            for inc in range(256):
                if lcg_stream(start, mult, inc, len(target)) == wanted:
                    return start, mult, inc
    raise RuntimeError("alignment not found")


def main() -> None:
    exe = Path("player.exe").read_bytes()
    transmission = Path("transmission.dat").read_bytes()

    start, mult, inc = find_alignment(transmission[:4])
    assert (start, mult, inc) == (139, 67, 249)

    code = exe[va_to_file_offset(CHECK_FUNC):va_to_file_offset(CHECK_FUNC_END)]
    key = fnv1a_32(code).to_bytes(4, "little")

    enc_flag = exe[va_to_file_offset(ENC_FLAG_VA):va_to_file_offset(ENC_FLAG_VA) + ENC_FLAG_LEN]
    flag = bytes(b ^ key[i & 3] for i, b in enumerate(enc_flag)).rstrip(b"\x00")
    print(flag.decode())


if __name__ == "__main__":
    main()
