#!/usr/bin/env python3
import base64
import gzip
import re
from pathlib import Path

from Evtx.Evtx import Evtx


EVTX_PATH = Path("Credential Access/phish_windows_credentials_powershell_scriptblockLog_4104.evtx")


def extract_script(path: Path) -> str:
    with Evtx(str(path)) as log:
        first = next(log.records()).xml()
    match = re.search(r"FromBase64String\('([^']+)'\)", first)
    if not match:
        raise RuntimeError("Base64 stage-1 payload not found")
    return gzip.decompress(base64.b64decode(match.group(1))).decode()


def main() -> None:
    script = extract_script(EVTX_PATH)

    func_match = re.search(r"function\s+([A-Za-z0-9_-]+)\s*\{", script)
    marker_match = re.search(r"(R)\{([^}]+)\}", script)
    if not func_match or not marker_match:
        raise RuntimeError("Failed to recover function name or marker")

    flag = f"grodno{{{func_match.group(1)}_{marker_match.group(1)}{marker_match.group(2)}}}"
    print(flag)


if __name__ == "__main__":
    main()
