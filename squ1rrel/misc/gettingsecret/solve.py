#!/usr/bin/env python3
import os
import shutil
import string
import subprocess
from pathlib import Path


PART1_BLOB = "920984763899e54c82db401ec6d9db7b5540754a"
PART2_BLOB = "bcffeb3eb0fadbcb95c62d2abb612e4b7fef6b0c"
PART3_BLOB = "93bbb5c17dea12d25aedf03b8996935a5fc950ba"
PACK_BASENAME = "34e499dda06b2d6fece2ef31f097e5350818f421"


def run_git(*args: str) -> str:
    out = subprocess.check_output(["git", *args], text=True)
    return out.strip()


def ensure_pack_available() -> None:
    git_dir = Path(".git")
    src_pack = git_dir / "secret" / "knapsack.pack"
    src_idx = git_dir / "secret" / "knapsack.idx"
    dst_dir = git_dir / "objects" / "pack"
    dst_pack = dst_dir / f"pack-{PACK_BASENAME}.pack"
    dst_idx = dst_dir / f"pack-{PACK_BASENAME}.idx"

    dst_dir.mkdir(parents=True, exist_ok=True)

    if src_pack.exists() and not dst_pack.exists():
        shutil.copy2(src_pack, dst_pack)
    if src_idx.exists() and not dst_idx.exists():
        shutil.copy2(src_idx, dst_idx)

    # If idx doesn't exist yet, generate it from the pack.
    if dst_pack.exists() and not dst_idx.exists():
        subprocess.check_call(["git", "index-pack", str(dst_pack)])


def b62decode(s: str) -> bytes:
    alphabet = string.digits + string.ascii_uppercase + string.ascii_lowercase
    table = {c: i for i, c in enumerate(alphabet)}
    n = 0
    for ch in s:
        if ch not in table:
            raise ValueError(f"Invalid base62 char: {ch!r}")
        n = n * 62 + table[ch]
    if n == 0:
        return b""
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def main() -> None:
    if not Path(".git").exists():
        raise SystemExit("Run this script inside the challenge repo (contains .git).")

    ensure_pack_available()

    part1 = run_git("cat-file", "-p", PART1_BLOB)
    part2 = run_git("cat-file", "-p", PART2_BLOB)
    part3 = run_git("cat-file", "-p", PART3_BLOB)

    flag = (b62decode(part1) + b62decode(part2) + b62decode(part3)).decode("utf-8")
    print(flag)


if __name__ == "__main__":
    main()
