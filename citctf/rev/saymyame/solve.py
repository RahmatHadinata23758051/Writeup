#!/usr/bin/env python3
import re
import subprocess
from pathlib import Path

BINARY = Path(__file__).with_name("saymyname")
TARGET_NAME = "Bartholomew Demetrius Jamarion Kensington Blackwood Montague Devereaux Jackson-Fitzwilliam the XXVII"


def main() -> None:
    if not BINARY.exists():
        raise SystemExit("Binary 'saymyname' tidak ditemukan di direktori ini")

    proc = subprocess.run(
        [str(BINARY)],
        input=TARGET_NAME + "\n",
        text=True,
        capture_output=True,
        check=False,
    )

    output = proc.stdout + proc.stderr
    match = re.search(r"CIT\{[^}]+\}", output)
    if not match:
        print(output, end="")
        raise SystemExit("Flag tidak ditemukan dari output binary")

    print(match.group(0))


if __name__ == "__main__":
    main()
