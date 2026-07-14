#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path


FLAG_RE = re.compile(r"bronco\{[^}\r\n]+\}")


def build_payload() -> bytes:
    """
    Hidden win conditions recovered from the binary:

    - 5 valid choices
    - talk exactly 3 times
    - scratch exactly once
    - eat exactly once
    - total length of the three talk messages is 32
    - final score is 45
    - mood remains positive

    Message lengths: 10 + 10 + 12 = 32.
    """
    return b"".join(
        [
            b"\n",                  # Press Enter to begin
            b"1\n", b"a" * 10 + b"\n",
            b"1\n", b"b" * 10 + b"\n",
            b"1\n", b"c" * 12 + b"\n",
            b"2\n",
            b"3\n",
        ]
    )


def solve(binary_path: Path) -> tuple[str, str]:
    if not binary_path.is_file():
        raise FileNotFoundError(f"Binary tidak ditemukan: {binary_path}")

    binary_path.chmod(binary_path.stat().st_mode | 0o111)

    result = subprocess.run(
        [str(binary_path.resolve())],
        input=build_payload(),
        capture_output=True,
        timeout=10,
    )

    output = result.stdout.decode("utf-8", errors="replace")

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Program berhenti dengan exit code {result.returncode}\n"
            f"stdout:\n{output}\n"
            f"stderr:\n{stderr}"
        )

    match = FLAG_RE.search(output)
    if not match:
        raise ValueError(f"Flag tidak ditemukan pada output:\n{output}")

    return match.group(0), output


def main() -> None:
    binary_path = Path(sys.argv[1] if len(sys.argv) > 1 else "./cat-sim-linux")
    flag, _ = solve(binary_path)
    print(flag)


if __name__ == "__main__":
    main()
