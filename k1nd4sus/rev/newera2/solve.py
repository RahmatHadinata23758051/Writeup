#!/usr/bin/env python3
import argparse
import numpy as np


def decode_hamming74_codeword(codeword: np.ndarray) -> np.ndarray:
    b = codeword.copy()
    s1 = b[0] ^ b[2] ^ b[4] ^ b[6]
    s2 = b[1] ^ b[2] ^ b[5] ^ b[6]
    s4 = b[3] ^ b[4] ^ b[5] ^ b[6]
    pos = s1 + (s2 << 1) + (s4 << 2)
    if pos != 0:
        b[pos - 1] ^= 1
    return np.array([b[2], b[4], b[5], b[6]], dtype=np.uint8)


def decode_flag(path: str, sps: int = 8) -> str:
    raw = np.fromfile(path, dtype=np.float32)
    if raw.size % 2 != 0:
        raise ValueError("Format IQ tidak valid (jumlah float ganjil)")

    i_samples = raw[0::2]
    if i_samples.size % sps != 0:
        raise ValueError(f"Jumlah sample I ({i_samples.size}) tidak habis dibagi sps={sps}")

    symbols = i_samples.reshape(-1, sps).mean(axis=1)
    bits = (symbols > 0).astype(np.uint8)

    if bits.size % 7 != 0:
        raise ValueError("Jumlah bit tidak habis dibagi 7 untuk Hamming(7,4)")

    codewords = bits.reshape(-1, 7)
    nibbles = np.array([decode_hamming74_codeword(cw) for cw in codewords], dtype=np.uint8)

    nib_vals = nibbles.dot(1 << np.arange(3, -1, -1)).astype(np.uint8)
    if nib_vals.size % 2 != 0:
        raise ValueError("Jumlah nibble ganjil, tidak bisa dibentuk byte")

    data = ((nib_vals[0::2] << 4) | nib_vals[1::2]).astype(np.uint8).tobytes()
    return data.decode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description="Solve New Era (Part 2)")
    parser.add_argument("-i", "--input", default="intercepted_signal.iq", help="Path file IQ")
    parser.add_argument("--sps", type=int, default=8, help="Samples per symbol")
    args = parser.parse_args()

    print(decode_flag(args.input, args.sps))


if __name__ == "__main__":
    main()
