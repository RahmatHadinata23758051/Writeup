#!/usr/bin/env python3
import argparse
import numpy as np


def decode_flag(path: str, sps: int = 8) -> str:
    raw = np.fromfile(path, dtype=np.float32)
    if raw.size % 2 != 0:
        raise ValueError("Jumlah float ganjil, format IQ tidak valid")

    i_samples = raw[0::2]
    if i_samples.size % sps != 0:
        raise ValueError(f"Jumlah sample I ({i_samples.size}) tidak habis dibagi sps={sps}")

    symbols = i_samples.reshape(-1, sps).mean(axis=1)
    bits = (symbols > 0).astype(np.uint8)

    if bits.size % 8 != 0:
        raise ValueError("Jumlah bit tidak habis dibagi 8")

    data = bits.reshape(-1, 8).dot(1 << np.arange(7, -1, -1)).astype(np.uint8).tobytes()
    return data.decode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description="Decode New Era (Part 1) intercepted IQ signal")
    parser.add_argument("-i", "--input", default="intercepted_signal.iq", help="Path file IQ (default: intercepted_signal.iq)")
    parser.add_argument("--sps", type=int, default=8, help="Samples per symbol (default: 8)")
    args = parser.parse_args()

    flag = decode_flag(args.input, args.sps)
    print(flag)


if __name__ == "__main__":
    main()
