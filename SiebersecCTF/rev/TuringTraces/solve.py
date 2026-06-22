#!/usr/bin/env python3
import re
import subprocess
from pathlib import Path


MASK = (1 << 64) - 1
C1 = 0xBDD640FB06671AD1
MUL = 0x1C80317FA3B1799D
C2 = 0x3EB13B9046685257
TARGET = 0xCC4A46BF3E0E326C


def rol64(value: int, count: int) -> int:
    return ((value << count) & MASK) | (value >> (64 - count))


def ror64(value: int, count: int) -> int:
    return ((value >> count) | ((value << (64 - count)) & MASK)) & MASK


def recover_license() -> int:
    inv = pow(MUL, -1, 1 << 64)
    value = TARGET ^ C2
    value = ror64(value, 17)
    value = (value * inv) & MASK
    return value ^ C1


def main() -> None:
    root = Path(__file__).resolve().parent
    chall = root / "chall"
    license_path = root / "license.key"

    license_value = recover_license()
    license_path.write_text(f"{license_value:016x}\n", encoding="ascii")
    chall.chmod(chall.stat().st_mode | 0o111)

    proc = subprocess.run(
        [str(chall)],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )

    output = proc.stdout
    print(output, end="")

    match = re.search(r"sctf\\{[^}]+\\}", output)
    if not match:
        raise SystemExit("flag not found in binary output")

    print(f"\n[+] license.key = {license_value:016x}")
    print(f"[+] flag = {match.group(0)}")


if __name__ == "__main__":
    main()
