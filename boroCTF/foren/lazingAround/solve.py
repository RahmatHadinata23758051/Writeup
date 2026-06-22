#!/usr/bin/env python3
import re
import subprocess
from pathlib import Path


IMAGE = Path("chall")
LS_RE = re.compile(
    r"\s*(\d+)\s+\d+ \(\d+\)\s+\d+\s+\d+\s+(\d+) .* ((?:entry|exit)_log_(\d+)\.txt)$"
)
BLOCK_RE = re.compile(r"\(0\):(\d+)")


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL)


def read_block(image: Path, block: int) -> bytes:
    return subprocess.check_output(
        ["dd", f"if={image}", "bs=4096", f"skip={block}", "count=1", "status=none"],
        stderr=subprocess.DEVNULL,
    )


def main() -> None:
    listing = run("debugfs", "-R", "ls -l /", str(IMAGE))
    parts: list[tuple[int, bytes]] = []

    for line in listing.splitlines():
        match = LS_RE.match(line)
        if not match:
            continue

        inode = int(match.group(1))
        size = int(match.group(2))
        number = int(match.group(4))

        stat = run("debugfs", "-R", f"stat <{inode}>", str(IMAGE))
        block_match = BLOCK_RE.search(stat)
        if not block_match:
            continue

        block = int(block_match.group(1))
        data = read_block(IMAGE, block)
        slack = bytes(b for b in data[size:] if b != 0)
        if slack:
            parts.append((number, slack))

    flag = "".join(chunk.decode("latin1") for _, chunk in sorted(parts))
    print(flag)


if __name__ == "__main__":
    main()
