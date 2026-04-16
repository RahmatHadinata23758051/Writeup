#!/usr/bin/env python3
import re
import subprocess
import sys


def main() -> int:
    wav = "rot.wav"
    if len(sys.argv) > 1:
        wav = sys.argv[1]

    cmd = [
        "multimon-ng",
        "-q",
        "-t",
        "wav",
        "-a",
        "POCSAG512",
        wav,
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        print("Error: multimon-ng tidak ditemukan", file=sys.stderr)
        return 1

    out = (proc.stdout or "") + "\n" + (proc.stderr or "")

    m = re.search(r"sillyCTF\{[^}]+\}", out)
    if not m:
        print("Flag tidak ditemukan")
        return 1

    print(m.group(0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
