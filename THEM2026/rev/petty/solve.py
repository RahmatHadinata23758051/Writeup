#!/usr/bin/env python3
from pathlib import Path
import base64

BIN = Path('crab.exe')
START = 0x2A009
END = 0x2AC34
XOR_KEY = 0x69

TARGET = (
    241, 250, 126, 93, 101, 32, 92, 189, 201, 144, 156, 157, 61, 197, 242, 125,
    64, 195, 80, 221, 116, 218, 238, 61, 89, 80, 154, 29, 13, 138, 66, 253,
    209, 112, 64, 93, 69, 211, 66, 189, 41, 42, 242, 157, 29, 79, 204, 125,
    161, 28, 162, 221, 85, 95, 192, 61, 184, 252, 246, 29, 109, 63, 170, 253,
    48, 220, 178, 93, 165, 47, 180, 189, 8, 188, 198, 157, 125, 255, 40, 125,
    129, 138, 142, 221, 181, 239, 36, 61, 153, 106, 194, 29, 77, 143, 156, 253,
    17, 74, 146, 93, 133, 140, 130, 189, 104, 60, 38, 157, 93, 122, 26, 125,
    225, 63, 240, 221, 149, 90, 22, 61, 248, 252, 54, 29, 173, 63, 248, 253,
    113, 255, 224, 93, 229, 26, 226, 189, 72, 188, 10, 157, 189, 207, 108, 125,
    193, 138, 252, 221, 244, 204, 106, 61, 216, 124, 6, 29, 141, 186, 194, 253,
    81, 127, 192, 93, 197, 154, 212, 189, 169, 60, 110, 157, 156, 108, 70, 125,
    32, 28, 34, 221, 213, 95, 64, 61, 57, 234, 118, 29, 236, 44, 56, 253,
    177, 131, 62, 14,
)

STD_ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
CUSTOM_ALPHA = 'HIJKLMNOPQRSTUVWXYZABCDEFGhijklmnopqrstuvwxyzabcdefg6789012345+/'


def extract_embedded_pyc() -> bytes:
    data = BIN.read_bytes()
    pyc = bytes(b ^ XOR_KEY for b in data[START:END])
    if pyc[:4] != bytes.fromhex('cb0d0d0a'):
        raise RuntimeError('embedded pyc magic not found')
    return pyc


def solve() -> str:
    # The embedded Python verifier transforms custom_b64 bytes with:
    # key(i) = (13*i^3 + 3*i^2 + 7*i + 420) & 0xff
    custom_b64 = ''.join(
        chr(value ^ ((13 * (i ** 3) + 3 * (i ** 2) + 7 * i + 420) & 0xff))
        for i, value in enumerate(TARGET)
    )
    std_b64 = custom_b64.translate(str.maketrans(CUSTOM_ALPHA, STD_ALPHA))
    spaced_hex = base64.b64decode(std_b64).decode()
    return bytes.fromhex(spaced_hex.replace(' ', '')).decode()


if __name__ == '__main__':
    extract_embedded_pyc()
    print(solve())
