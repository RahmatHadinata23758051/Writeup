#!/usr/bin/env python3
import re
import subprocess
import sys
from pathlib import Path


def run_regripper(hive_path: Path) -> str:
    cmd = ["regripper", "-r", str(hive_path), "-p", "run"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"regripper failed: {res.stderr.strip()}")
    return res.stdout


def extract_persistence_name(rr_output: str) -> str:
    # Target format line example:
    #   AzureTenant - "C:\\Users\\kurt\\AppData\\Roaming\\fj3493.exe"
    m = re.search(r"^\s*([A-Za-z0-9_\-]+)\s+-\s+\"[A-Za-z]:\\\\.*?\"\s*$", rr_output, re.M)
    if m:
        return m.group(1)

    # Fallback: specifically grab the suspicious value if present
    m2 = re.search(r"^\s*(AzureTenant)\s+-\s+", rr_output, re.M)
    if m2:
        return m2.group(1)

    raise ValueError("Could not find persistence value name in Run key output")


def main() -> int:
    default_hive = Path(__file__).resolve().parent / "challenge.dat"
    hive = Path(sys.argv[1]) if len(sys.argv) > 1 else default_hive

    if not hive.exists():
        print(f"[!] Hive not found: {hive}")
        return 1

    try:
        out = run_regripper(hive)
        name = extract_persistence_name(out)
        print(f"Persistence name: {name}")
        print(f"CIT{{{name}}}")
        return 0
    except Exception as e:
        print(f"[!] Error: {e}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
