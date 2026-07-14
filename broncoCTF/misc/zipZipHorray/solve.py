#!/usr/bin/env python3
"""Extract Zip, Zip, Hooray! archive layers and print the original flag."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent
START_ARCHIVE = ROOT / "chall.zip"
OUTPUT_DIR = ROOT / ".solve_layers"


def run(*args: str) -> str:
    """Run 7z quietly and return its stdout, failing on extraction errors."""
    result = subprocess.run(args, text=True, capture_output=True)
    if result.returncode > 1:  # 7z uses 1 for a non-fatal warning.
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout


def archive_info(path: Path) -> tuple[str, str | None]:
    """Return 7z's archive type and the first contained filename, if listed."""
    listing = run("7z", "l", "-slt", str(path))
    archive_type = re.search(r"^Type = (.+)$", listing, re.MULTILINE)
    if not archive_type:
        raise RuntimeError(f"Could not identify archive type: {path}")

    entry = None
    parts = listing.split("----------", 1)
    if len(parts) == 2:
        match = re.search(r"^Path = (.+)$", parts[1], re.MULTILINE)
        if match:
            entry = match.group(1)
    return archive_type.group(1), entry


def main() -> None:
    if not START_ARCHIVE.is_file():
        raise SystemExit(f"Missing input archive: {START_ARCHIVE.name}")

    shutil.rmtree(OUTPUT_DIR, ignore_errors=True)
    # exist_ok also makes a rerun safe if a previous interrupted invocation
    # recreated the directory between cleanup and this call.
    OUTPUT_DIR.mkdir(exist_ok=True)
    current = START_ARCHIVE

    for layer in range(1, 3001):
        archive_type, first_entry = archive_info(current)
        destination = OUTPUT_DIR / f"{layer:04d}"
        command = ["7z", "x", "-y", f"-o{destination}"]

        # The challenge hint: each encrypted 7z uses its first entry name as password.
        if archive_type == "7z" and first_entry:
            command.append(f"-p{first_entry}")
        command.append(str(current))
        run(*command)

        files = [path for path in destination.rglob("*") if path.is_file()]
        if len(files) != 1:
            raise RuntimeError(f"Layer {layer}: expected one extracted file, got {files}")
        current = files[0]

        file_type = subprocess.check_output(["file", "-b", str(current)], text=True).lower()
        if not any(marker in file_type for marker in ("archive", "compressed data", "tar ")):
            print(current.read_text().strip())
            return

    raise RuntimeError("Stopped after 3000 layers without finding the original file")


if __name__ == "__main__":
    main()
