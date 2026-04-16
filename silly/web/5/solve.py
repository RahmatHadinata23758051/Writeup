#!/usr/bin/env python3
import base64
import re
import time

import requests

BASE_URL = "https://goingbackintime.sillyctf.psuccso.org"
START_PATH = "/2000/"
SLEEP_SEC = 0.5
MAX_STEPS = 500

YEAR_RE = re.compile(r"Welcome to\s*(\d+)!", re.I)
CSS_RE = re.compile(r'href="(\d+)\.css"', re.I)
B64_RE = re.compile(r"([A-Za-z0-9+/]{16,}={0,2})")
FLAG_RE = re.compile(r"(sillyCTF\{[^}]+\}|flag\{[^}]+\}|ctf\{[^}]+\})", re.I)


def try_decode_base64_candidates(text: str):
    for token in B64_RE.findall(text):
        try:
            raw = base64.b64decode(token, validate=True)
            decoded = raw.decode("utf-8", errors="ignore")
        except Exception:
            continue
        m = FLAG_RE.search(decoded)
        if m:
            return m.group(1), token
    return None, None


def main() -> int:
    s = requests.Session()
    path = START_PATH

    for step in range(MAX_STEPS):
        url = BASE_URL + path
        r = s.get(url, timeout=15)

        if r.status_code != 200:
            print(f"[!] Non-200 at step {step}: {r.status_code} -> {url}")
            return 1

        text = r.text
        direct = FLAG_RE.search(text)
        if direct:
            print(direct.group(1))
            return 0

        found, token = try_decode_base64_candidates(text)
        if found:
            print(found)
            return 0

        ym = YEAR_RE.search(text)
        cm = CSS_RE.search(text)
        if not ym or not cm:
            print(f"[!] Parse failed at step {step} -> {url}")
            print("[i] Response snippet:")
            print(text[:800])
            return 1

        prev_year = cm.group(1)
        path += f"{prev_year}/"
        time.sleep(SLEEP_SEC)

    print("[!] Reached MAX_STEPS without finding flag")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
