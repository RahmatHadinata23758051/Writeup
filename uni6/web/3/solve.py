#!/usr/bin/env python3
import re
import sys
from urllib.parse import urljoin
from urllib.request import Request, urlopen

BASE = "https://lwy-stream-lab.vercel.app"
UA = "Mozilla/5.0 (CTF Solver)"
CHUNK_RE = re.compile(r"/_next/static/chunks/[^\"']+\.js")
FULL_FLAG_RE = re.compile(r"FLAG\{[^}]+\}")
BRACED_TOKEN_RE = re.compile(r"\{[A-Z0-9_]{6,}\}")


def http_get(url: str) -> str:
    req = Request(url, headers={"User-Agent": UA})
    with urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def extract_flag_from_js(js: str) -> str | None:
    m = FULL_FLAG_RE.search(js)
    if m:
        return m.group(0)

    # Some bundles split the flag display into two adjacent strings: " FLAG", "{...}".
    for token in BRACED_TOKEN_RE.finditer(js):
        left = js[max(0, token.start() - 100):token.start()]
        if "FLAG" in left:
            return f"FLAG{token.group(0)}"
    return None


def main() -> int:
    try:
        home = http_get(urljoin(BASE, "/home"))
    except Exception as e:
        print(f"[!] Failed to fetch /home: {e}")
        return 1

    chunks = sorted(set(CHUNK_RE.findall(home)))
    if not chunks:
        print("[!] No JS chunks found")
        return 1

    for path in chunks:
        try:
            js = http_get(urljoin(BASE, path))
        except Exception:
            continue

        flag = extract_flag_from_js(js)
        if flag:
            print(flag)
            return 0

    print("[!] Flag not found")
    return 1


if __name__ == "__main__":
    sys.exit(main())
