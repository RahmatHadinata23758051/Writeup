# Take Two

## Challenge

**Title:** Take Two  
**Category:** Cryptography  
**Flag:** `H7CTF{0d99d7d0-dee6-443f-be85-04de85f52089}`

## Description

Helios firmware menggunakan sistem notary berbasis LMS/WOTS untuk menandatangani firmware. Device hanya akan menjalankan firmware yang memiliki signature valid terhadap Merkle root yang dipercaya.

Service menyediakan beberapa endpoint:

```text
GET /root
POST /sign {firmware}
POST /rollback
POST /deploy {firmware, sig}
```

Endpoint `/sign` hanya mau menandatangani firmware benign. Firmware yang mengandung string `BACKDOOR` akan ditolak.

Tujuan challenge adalah membuat signature valid untuk firmware backdoored, lalu deploy firmware tersebut untuk mendapatkan flag.

## Source Code Analysis

Skema yang digunakan adalah LMS-style signature dengan WOTS sebagai one-time signature pada setiap leaf Merkle tree.

Parameter penting:

```python
N = 32
W = 16
LEN1 = 64
LEN2 = 3
LEN = 67
TREE_H = 4
```

Karena `TREE_H = 4`, total leaf yang tersedia adalah:

```text
2^4 = 16 leaves
```

Setiap leaf adalah satu WOTS keypair dan seharusnya hanya digunakan satu kali.

Fungsi signing:

```python
def sign(self, msg, leaf=None):
    q = self.ctr if leaf is None else leaf
    sig = {
        "leaf": q,
        "wots": wots_sign(self.sk[q], msg),
        "path": auth_path(self.levels, q)
    }
    if leaf is None:
        self.ctr += 1
    return sig
```

Signature berisi:

```text
leaf index
WOTS signature
Merkle authentication path
```

Verification menghitung ulang WOTS public key dari signature, lalu menghitung Merkle root dari leaf tersebut.

## Vulnerability

WOTS adalah **one-time signature**. Artinya, satu WOTS private key hanya aman digunakan untuk menandatangani satu message.

Pada challenge ini terdapat endpoint:

```text
POST /rollback
```

Endpoint tersebut dapat mengembalikan signing counter. Akibatnya, leaf WOTS yang sama dapat digunakan berkali-kali untuk menandatangani firmware benign yang berbeda.

Ini menyebabkan **WOTS key reuse**.

Pada WOTS, signature untuk setiap digit adalah:

```text
sig[i] = chain(sk[i], msg_digit[i])
```

Karena hash chain hanya bisa maju, dari signature dengan digit `d`, kita bisa membuat signature untuk digit target `t` jika:

```text
d <= t
```

Caranya:

```text
forged_sig[i] = chain(sig[i], t - d)
```

Dengan meminta banyak signature benign pada leaf yang sama, kita bisa mengumpulkan komponen WOTS yang cukup untuk membentuk signature valid bagi firmware target yang mengandung `BACKDOOR`.

## Exploit Strategy

Target firmware:

```text
HELIOS_RELEASE_2.0_BACKDOOR
```

Strategi exploit:

1. Ambil Merkle root dari `/root`.
2. Tentukan digit WOTS untuk firmware target.
3. Reset signing counter menggunakan `/rollback`.
4. Minta signature untuk banyak firmware benign.
5. Setelah setiap signature, panggil `/rollback` agar leaf yang sama dipakai ulang.
6. Untuk setiap komponen WOTS, simpan signature jika digit firmware benign `<=` digit target.
7. Setelah semua 67 komponen WOTS tertutup, buat forged signature.
8. Verifikasi forged signature secara lokal.
9. Submit firmware backdoored dan forged signature ke `/deploy`.

## Solver

```python
#!/usr/bin/env python3
import requests
import hashlib
import secrets
import json
import sys
import time

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "https://web-e9fb98b5fb5ba484.web.h7tex.com"

N = 32
W = 16
LEN1 = 64
LEN2 = 3
LEN = LEN1 + LEN2

TARGET_FIRMWARE = "HELIOS_RELEASE_2.0_BACKDOOR"

def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def chain(x: bytes, steps: int) -> bytes:
    for _ in range(steps):
        x = H(x)
    return x

def msg_digits(msg: bytes):
    d = H(msg)
    digs = []

    for byte in d:
        digs.append(byte >> 4)
        digs.append(byte & 0xF)

    c = sum(W - 1 - x for x in digs)
    digs += [(c >> 8) & 0xF, (c >> 4) & 0xF, c & 0xF]

    return digs

def wots_pk_from_sig(msg: bytes, sig):
    digs = msg_digits(msg)
    return H(b"".join(chain(sig[i], W - 1 - digs[i]) for i in range(LEN)))

def merkle_root_from_leaf(leaf: bytes, idx: int, path):
    node = leaf

    for sib in path:
        if idx & 1 == 0:
            node = H(b"\x01" + node + sib)
        else:
            node = H(b"\x01" + sib + node)

        idx >>= 1

    return node

def verify(msg: bytes, sig_obj, root_hex: str):
    wots = [bytes.fromhex(x) for x in sig_obj["wots"]]
    path = [bytes.fromhex(x) for x in sig_obj["path"]]
    leaf_idx = int(sig_obj["leaf"])

    leaf = H(b"\x00" + wots_pk_from_sig(msg, wots))
    root = merkle_root_from_leaf(leaf, leaf_idx, path)

    return root.hex() == root_hex

def rollback(times=1):
    for _ in range(times):
        requests.post(BASE + "/rollback", timeout=10)

def find_sig_obj(data):
    if isinstance(data, dict):
        if all(k in data for k in ["leaf", "wots", "path"]):
            return data

        for key in ["sig", "signature"]:
            if key in data and isinstance(data[key], dict):
                if all(k in data[key] for k in ["leaf", "wots", "path"]):
                    return data[key]

        for v in data.values():
            got = find_sig_obj(v)
            if got:
                return got

    return None

def sign_firmware(firmware: str):
    r = requests.post(
        BASE + "/sign",
        json={"firmware": firmware},
        timeout=15,
    )

    data = r.json()
    sig = find_sig_obj(data)

    if sig is None:
        print("[-] Cannot parse sign response:")
        print(json.dumps(data, indent=2))
        return None

    return sig

def deploy(firmware: str, sig_obj):
    r = requests.post(
        BASE + "/deploy",
        json={
            "firmware": firmware,
            "sig": sig_obj,
        },
        timeout=15,
    )

    print("[*] Deploy HTTP", r.status_code)

    try:
        print(json.dumps(r.json(), indent=2))
    except Exception:
        print(r.text)

def main():
    print("[*] Target:", BASE)

    root_data = requests.get(BASE + "/root", timeout=15).json()
    root_hex = root_data["root"]

    print("[*] Root:", root_hex)
    print("[*] Target firmware:", TARGET_FIRMWARE)

    target_msg = TARGET_FIRMWARE.encode()
    target_digits = msg_digits(target_msg)

    rollback(32)

    chosen = [None] * LEN
    chosen_digit = [None] * LEN

    base_leaf = None
    base_path = None

    for attempt in range(1, 501):
        firmware = f"HELIOS_RELEASE_2.0_CLEAN_{attempt}_{secrets.token_hex(12)}"

        sig_obj = sign_firmware(firmware)

        if sig_obj is None:
            return

        leaf = int(sig_obj["leaf"])

        if base_leaf is None:
            base_leaf = leaf
            base_path = sig_obj["path"]
            print("[*] Reusing leaf:", base_leaf)

        if leaf != base_leaf:
            rollback(32)
            continue

        wots = [bytes.fromhex(x) for x in sig_obj["wots"]]
        digs = msg_digits(firmware.encode())

        updated = 0

        for i in range(LEN):
            if digs[i] <= target_digits[i]:
                if chosen[i] is None or digs[i] < chosen_digit[i]:
                    chosen[i] = wots[i]
                    chosen_digit[i] = digs[i]
                    updated += 1

        covered = sum(x is not None for x in chosen)

        print(f"[*] try={attempt:03d} covered={covered}/{LEN} updated={updated}")

        if covered == LEN:
            print("[+] All WOTS components covered")
            break

        rollback(1)
        time.sleep(0.03)

    if any(x is None for x in chosen):
        print("[-] Failed to cover all target digits")
        missing = [i for i, x in enumerate(chosen) if x is None]
        print("[*] Missing indexes:", missing)
        return

    forged_wots = []

    for i in range(LEN):
        src = chosen[i]
        src_d = chosen_digit[i]
        tgt_d = target_digits[i]

        forged = chain(src, tgt_d - src_d)
        forged_wots.append(forged.hex())

    forged_sig = {
        "leaf": base_leaf,
        "wots": forged_wots,
        "path": base_path,
    }

    print("[*] Verifying forged signature locally...")

    if verify(target_msg, forged_sig, root_hex):
        print("[+] Local verify OK")
    else:
        print("[-] Local verify failed")
        return

    print("[*] Deploying forged BACKDOOR firmware...")
    deploy(TARGET_FIRMWARE, forged_sig)

if __name__ == "__main__":
    main()
```

## Running the Solver

```bash
python3 solve.py
```

Output akhir:

```text
[+] All WOTS components covered
[*] Verifying forged signature locally...
[+] Local verify OK
[*] Deploying forged BACKDOOR firmware...
{
  "ok": true,
  "flag": "H7CTF{0d99d7d0-dee6-443f-be85-04de85f52089}"
}
```

## Result

Forged firmware:

```text
HELIOS_RELEASE_2.0_BACKDOOR
```

berhasil dibuat signature-nya menggunakan reuse leaf WOTS yang sama.

Flag:

```text
H7CTF{0d99d7d0-dee6-443f-be85-04de85f52089}
```


## Flag

```text
H7CTF{0d99d7d0-dee6-443f-be85-04de85f52089}
```
