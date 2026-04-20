#!/usr/bin/env python3
import re
import subprocess

BIN = "./catacombs"
SEQ = [
    "openat",
    "mmap",
    "ioctl",
    "read",
    "futex",
    "clone",
    "openat",
    "ioctl",
    "read",
    "close",
]


def run_solver() -> str:
    payload = "script " + " ".join(SEQ) + "\nsubmit\n"
    out = subprocess.check_output([BIN], input=payload, text=True)
    m = re.search(r"CIT\{[^\n\r}]+\}", out)
    if not m:
        raise RuntimeError("Flag not found. Full output:\n" + out)
    return m.group(0)


if __name__ == "__main__":
    print(run_solver())
