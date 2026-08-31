#!/usr/bin/env python3

import hashlib
import os
import re
import sys

import requests


BASE_TICKET_1337 = (
    "gonKBqlDdPr3Kg29oXObMZjNEm18pWG1lxAM9GBLJyK43DroYXZ27egV10dVpvqb"
    "Namw6OEjRPg8kznWv6zJnq7BlA4wkRaVyDYLxdNG6rVMy7"
)
ALPHABET = "12346789ABDEGJKLMNOPRVWXYZabdgjklmnopqrvwxyz"
GUARDS = "05Qe"


def fetch_target_hash(session: requests.Session, base_url: str) -> str:
    resp = session.get(f"{base_url}/flag", timeout=10)
    if resp.status_code not in (200, 403):
        resp.raise_for_status()
    match = re.search(r"sha512\(Golden Ticket\) = ([0-9a-f]{128})", resp.text)
    if not match:
        raise RuntimeError("golden ticket hash not found")
    return match.group(1)


def build_golden_ticket(target_hash: str) -> str:
    prefix = BASE_TICKET_1337[1:53]
    suffix = BASE_TICKET_1337[58:]
    for d1 in ALPHABET:
        for d2 in ALPHABET:
            for d3 in ALPHABET:
                for g2 in GUARDS:
                    ticket = prefix + "eg" + d1 + d2 + d3 + g2 + suffix
                    if hashlib.sha512(ticket.encode()).hexdigest() == target_hash:
                        return ticket
    raise RuntimeError("no matching ticket found")


def main() -> int:
    base_url = sys.argv[1] if len(sys.argv) > 1 else os.environ.get(
        "TARGET_URL", "http://91.107.150.87:33617"
    )
    session = requests.Session()
    target_hash = fetch_target_hash(session, base_url)
    ticket = build_golden_ticket(target_hash)
    resp = session.get(f"{base_url}/flag", cookies={"ticket": ticket}, timeout=10)
    resp.raise_for_status()
    print(resp.text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
