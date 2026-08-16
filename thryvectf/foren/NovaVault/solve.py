#!/usr/bin/env python3
"""Recover the pre-containment KeePass value from NovaVault artifacts."""

from pathlib import Path
import re

from pykeepass import PyKeePass


ROOT = Path(__file__).resolve().parent
DUMP = ROOT / "NovaVault_DMP.dmp"
DB = ROOT / "NovaVault_DB.kdbx"


def recover_master_password(blob: bytes) -> str:
    # The crash artifact stores the useful characters in record-size fields:
    # cf 25 <ASCII> 00 00 00.  Most characters are repeated three times.
    chars = []
    for i in range(len(blob) - 5):
        if blob[i : i + 2] == b"\xcf%" and blob[i + 3 : i + 6] == b"\0\0\0":
            c = blob[i + 2]
            if 32 <= c < 127:
                chars.append(chr(c))

    # Collapse runs such as 000vvvaaa... while preserving the trailing
    # artifact text.  The password portion ends at the visible '!'.
    collapsed = "".join(ch for ch, _ in __import__("itertools").groupby(chars))
    prefix = collapsed.split("!", 1)[0] + "!"
    if not prefix.startswith("0va0x_"):
        raise ValueError(f"unexpected crash encoding: {collapsed!r}")
    return "N" + prefix


def main() -> None:
    password = recover_master_password(DUMP.read_bytes())
    db = PyKeePass(str(DB), password=password)

    for entry in db.entries:
        for old in entry.history:
            value = old.password or ""
            if value.startswith("Thryve{") and value.endswith("}"):
                print(value)
                return
    raise RuntimeError("no Thryve flag found in KeePass history")


if __name__ == "__main__":
    main()
