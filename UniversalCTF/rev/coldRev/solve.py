#!/usr/bin/env python3
from pathlib import Path
import argparse
import struct
import subprocess
import sys
import zlib


def rol8(x: int, n: int) -> int:
    n &= 7
    return ((x << n) | (x >> (8 - n))) & 0xFF


def ror8(x: int, n: int) -> int:
    n &= 7
    return ((x >> n) | (x << (8 - n))) & 0xFF


def solve_rom(path: str | Path) -> bytes:
    rom = Path(path).read_bytes()
    if len(rom) < 16 or rom[:4] != b"CS01":
        raise ValueError("bad ROM magic")

    version = rom[4]
    seed = rom[5]
    code_len = struct.unpack_from("<H", rom, 6)[0]
    entry = struct.unpack_from("<H", rom, 8)[0]
    expected_crc = struct.unpack_from("<I", rom, 10)[0]
    code = bytearray(rom[16:16 + code_len])

    if version != 1 or entry != 0:
        raise ValueError(f"unexpected ROM header: version={version}, entry={entry:#x}")
    got_crc = zlib.crc32(code) & 0xFFFFFFFF
    if got_crc != expected_crc:
        raise ValueError(f"CRC mismatch: got {got_crc:#x}, expected {expected_crc:#x}")

    # VM self-patch at PC 0x70:
    #   imm = rol8(seed, 5) ^ 0x3c
    imm = rol8(seed, 5) ^ 0x3C

    # VM decrypts 30 key bytes at memory 0x105 using evolving seed:
    #   seed = rol8(seed, 3) ^ 0x5b
    #   key[i] ^= seed
    x = seed
    for i in range(30):
        x = rol8(x, 3) ^ 0x5B
        code[0x105 + i] ^= x

    key = bytes(code[0x105:0x105 + 30])
    target = bytes(code[0x123:0x123 + 30])

    # Main check:
    #   transformed = rol8(input[i] ^ key[i], 3) ^ imm
    # So invert it:
    launch_code = bytes(ror8(t ^ imm, 3) ^ k for k, t in zip(key, target))
    return launch_code


def main() -> None:
    ap = argparse.ArgumentParser(description="Solve UCTF Cold Start / flightcomp mission.rom")
    ap.add_argument("rom", nargs="?", default="mission.rom")
    ap.add_argument("--flightcomp", default="./flightcomp", help="optional local binary to verify")
    ap.add_argument("--no-run", action="store_true", help="do not run local verifier")
    args = ap.parse_args()

    flag = solve_rom(args.rom)
    print(flag.decode())

    if not args.no_run and Path(args.flightcomp).exists():
        p = subprocess.run([args.flightcomp, args.rom], input=flag, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sys.stderr.write(p.stdout.decode(errors="replace"))
        if p.stderr:
            sys.stderr.write(p.stderr.decode(errors="replace"))


if __name__ == "__main__":
    main()
