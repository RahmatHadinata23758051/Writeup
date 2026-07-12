#!/usr/bin/env python3
"""Solver for JuniorCrypt Forensics - Philologist."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

PART_RE = re.compile(r"\bpart\s+(\d+)\b", re.IGNORECASE)


def run_git(repo: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("git tidak ditemukan di PATH") from exc
    except subprocess.CalledProcessError as exc:
        error = exc.stderr.strip() or "git command gagal"
        raise RuntimeError(error) from exc
    return result.stdout


def find_repo(root: Path) -> Path:
    if (root / ".git").is_dir():
        return root

    repositories = [path.parent for path in root.rglob(".git") if path.is_dir()]
    if not repositories:
        raise RuntimeError("repository Git tidak ditemukan")
    if len(repositories) > 1:
        raise RuntimeError(f"ditemukan lebih dari satu repository Git: {repositories}")
    return repositories[0]


def collect_parts(repo: Path) -> list[tuple[int, str]]:
    # Delimiter 0x1f avoids ambiguity with ordinary spaces in commit subjects.
    output = run_git(repo, "log", "--all", "--format=%H%x1f%s")
    parts: dict[int, str] = {}

    for line in output.splitlines():
        try:
            commit_hash, subject = line.split("\x1f", 1)
        except ValueError:
            continue

        match = PART_RE.search(subject)
        if match:
            index = int(match.group(1))
            parts[index] = commit_hash.strip()

    if not parts:
        raise RuntimeError("commit dengan subject 'part N' tidak ditemukan")

    indexes = sorted(parts)
    expected = list(range(indexes[-1] + 1))
    if indexes != expected:
        raise RuntimeError(f"urutan part tidak lengkap: ditemukan {indexes}")

    return [(index, parts[index]) for index in indexes]


def decode(parts: list[tuple[int, str]]) -> tuple[str, list[int]]:
    raw_bytes = [int(commit_hash[:2], 16) for _, commit_hash in parts]
    try:
        decoded = bytes(raw_bytes).decode("ascii")
    except UnicodeDecodeError as exc:
        raise RuntimeError("byte awal commit hash bukan ASCII valid") from exc
    return decoded, raw_bytes


def solve(source: Path) -> str:
    source = source.resolve()
    if not source.exists():
        raise RuntimeError(f"input tidak ditemukan: {source}")

    if source.is_dir():
        repo = find_repo(source)
        temporary = None
    elif zipfile.is_zipfile(source):
        temporary = tempfile.TemporaryDirectory(prefix=".philologist_", dir=Path.cwd())
        extract_root = Path(temporary.name)
        with zipfile.ZipFile(source) as archive:
            archive.extractall(extract_root)
        repo = find_repo(extract_root)
    else:
        raise RuntimeError("input harus berupa ZIP atau direktori repository")

    try:
        parts = collect_parts(repo)
        decoded, raw_bytes = decode(parts)

        print(f"[+] Repository : {repo}")
        for (index, commit_hash), value in zip(parts, raw_bytes):
            char = chr(value) if 32 <= value <= 126 else "."
            print(f"[+] part {index}: {commit_hash[:8]} -> 0x{value:02x} -> {char}")

        flag = f"grodno{{{decoded}}}"
        print(f"[+] Decoded    : {decoded}")
        print(f"[+] Flag       : {flag}")
        return flag
    finally:
        if temporary is not None:
            temporary.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract the Philologist flag from the Git commit hashes."
    )
    parser.add_argument(
        "source",
        nargs="?",
        default="filolog.zip",
        help="path ke filolog.zip atau direktori hasil ekstraksi",
    )
    args = parser.parse_args()

    try:
        solve(Path(args.source))
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
