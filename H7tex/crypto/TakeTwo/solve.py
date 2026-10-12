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
TREE_H = 4

# Firmware target yang tidak bisa diminta sign langsung
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
        try:
            requests.post(BASE + "/rollback", timeout=10)
        except Exception:
            pass

def find_sig_obj(data):
    """
    Support beberapa bentuk response:
    {"sig": {...}}
    {"signature": {...}}
    langsung {... leaf,wots,path ...}
    """
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

    try:
        data = r.json()
    except Exception:
        print("[-] Non-JSON sign response:", r.status_code, r.text[:300])
        return None, r

    sig = find_sig_obj(data)

    if sig is None:
        print("[-] Cannot parse sign response:")
        print(json.dumps(data, indent=2))
        return None, r

    return sig, r

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

    print("[*] Target digits:")
    print(target_digits)

    # Reset counter ke awal sebanyak mungkin.
    # Kalau rollback cuma decrement, 32x cukup buat balik ke leaf 0.
    rollback(32)

    chosen = [None] * LEN
    chosen_digit = [None] * LEN

    base_leaf = None
    base_path = None

    max_tries = 500

    for attempt in range(1, max_tries + 1):
        # Jangan mengandung BACKDOOR, karena /sign bakal refuse.
        fw = f"HELIOS_RELEASE_2.0_CLEAN_{attempt}_{secrets.token_hex(12)}"

        sig_obj, resp = sign_firmware(fw)

        if sig_obj is None:
            print("[-] Sign failed, status:", resp.status_code)
            print(resp.text[:300])
            return

        leaf = int(sig_obj["leaf"])

        if base_leaf is None:
            base_leaf = leaf
            base_path = sig_obj["path"]
            print(f"[*] Reusing leaf: {base_leaf}")

        if leaf != base_leaf:
            print(f"[!] Leaf changed from {base_leaf} to {leaf}, rolling back and skipping")
            rollback(32)
            continue

        wots = [bytes.fromhex(x) for x in sig_obj["wots"]]
        digs = msg_digits(fw.encode())

        updated = 0

        for i in range(LEN):
            # WOTS chain cuma bisa maju.
            # Dari signature digit d, kita bisa forge digit t kalau d <= t.
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

        # Inilah bug operational-nya: counter dikembalikan, jadi next sign reuse leaf sama.
        rollback(1)

        time.sleep(0.03)

    if any(x is None for x in chosen):
        print("[-] Failed to cover all target digits")
        missing = [i for i, x in enumerate(chosen) if x is None]
        print("[*] Missing indexes:", missing)
        print("[*] Target digits missing:", [target_digits[i] for i in missing])
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
        print(json.dumps(forged_sig, indent=2)[:1000])
        return

    print("[*] Deploying forged BACKDOOR firmware...")
    deploy(TARGET_FIRMWARE, forged_sig)

if __name__ == "__main__":
    main()
