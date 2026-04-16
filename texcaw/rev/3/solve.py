#!/usr/bin/env python3
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BIN = ROOT / "brokenquest"


def main() -> None:
    gdb_cmd = [
        "gdb",
        "-q",
        str(BIN),
        "-ex",
        "set pagination off",
        "-ex",
        "b *turn_in",
        "-ex",
        "run",
        "-ex",
        "set {int[8]} $rdi = {2,6,-4,6,0,4,-3,1}",
        "-ex",
        "c",
        "-ex",
        "quit",
    ]

    result = subprocess.run(
        gdb_cmd,
        input="0\n",
        text=True,
        capture_output=True,
        cwd=ROOT,
        check=True,
    )

    output = result.stdout + result.stderr
    match = re.search(r"texsaw\{[^}]+\}", output)
    if not match:
        raise SystemExit("flag not found")

    print(match.group(0))


if __name__ == "__main__":
    main()
