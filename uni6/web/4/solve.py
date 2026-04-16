#!/usr/bin/env python3
import re
import sys

import requests

BASE_URL = "https://lwy-see-ctf.vercel.app"
JS_PATH = "/js/app-core.js"
FLAG_RE = r"LWY\{[^}]+\}"


def main() -> int:
    url = BASE_URL + JS_PATH
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] request failed: {e}", file=sys.stderr)
        return 1

    m = re.search(FLAG_RE, resp.text)
    if not m:
        print("[!] flag not found", file=sys.stderr)
        return 2

    print(m.group(0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
