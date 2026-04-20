#!/usr/bin/env python3
import re
import socket

HOST = "challs.squ1rrel.dev"
PORT = 5002

SBOX = bytes.fromhex(
    "6c3978ce3df683dd30f4f55f138e351c4d936fc71b198043c6f0cb2fd147befa"
    "948aad5b867556b2095ea6ef11b1c2e0f8362051a11a7731080514e6df9e8dde"
    "6ea2c9d34e9dbb76923364ab91d757b03a4245079cdbc15216841fb3e78f34bf"
    "9a241299f92700508cd9f1eb3e740e4cc8cd62b55c90bcecfefdca211e586d23"
    "d296f37d7101497ce22e7948da38d085bd44ed984f0d250cb7677e6a2a157af2"
    "6606c553b92202a3882bb6296328b4e1e341cfa83ccc87615d034b6854f7a59b"
    "d895d5aaba824a1da97fe4c49fe87304eeff556b46178b10d489405a970f26ae"
    "e5a40ad62c60dca0a78165acfc0b1859af7069372de9b8fb3f323b72eac37bc0"
)

DELTA_INNER = 0x9F0CE81C
DELTA_OUTER = 0x19F3DC31
OUTER_TARGET = 0x3DC31000


def rotl32(x: int, n: int) -> int:
    n &= 31
    x &= 0xFFFFFFFF
    if n == 0:
        return x
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def sb_word(v: int) -> int:
    return (
        SBOX[v & 0xFF]
        | (SBOX[(v >> 8) & 0xFF] << 8)
        | (SBOX[(v >> 16) & 0xFF] << 16)
        | (SBOX[(v >> 24) & 0xFF] << 24)
    ) & 0xFFFFFFFF


def op127(x: int, h: int, state: int) -> tuple[int, int]:
    o = SBOX[(h ^ x ^ state) & 0xFF]
    o = ((o << 8) | o | (o << 16) | (o << 24)) & 0xFFFFFFFF
    o ^= x

    m = (state ^ h) & 31
    m = (rotl32(o, m) + ((sb_word(h) * h) & 0xFFFFFFFF)) & 0xFFFFFFFF

    o2 = m ^ state
    out = (sb_word(o2) ^ m) & 0xFFFFFFFF

    n2 = (m + state) & 0xFFFFFFFF
    state2 = (sb_word(n2) ^ o2) & 0xFFFFFFFF
    return out, state2


def F(nonce: bytes) -> bytes:
    w = [int.from_bytes(nonce[i * 4 : (i + 1) * 4], "little") for i in range(8)]

    # opcode funct7=126 side effect observed in emulator decoder
    state = w[0]

    outer = 0
    while outer != OUTER_TARGET:
        inner = outer
        for i in range(8):
            x = w[i] ^ inner
            h = w[(i + 1) & 7]
            w[i], state = op127(x, h, state)
            inner = (inner + DELTA_INNER) & 0xFFFFFFFF
        outer = (outer + DELTA_OUTER) & 0xFFFFFFFF

    out = b"".join(v.to_bytes(4, "little") for v in w)
    return out[:16]


def solve(host: str = HOST, port: int = PORT) -> str:
    with socket.create_connection((host, port), timeout=8) as sock:
        f = sock.makefile("rwb", buffering=0)

        banner = f.readline().decode("ascii", errors="ignore").rstrip("\n")
        print(banner)

        while True:
            line = f.readline()
            if not line:
                raise RuntimeError("connection closed")

            text = line.decode("ascii", errors="ignore").strip()

            m = re.match(r"round\s+\d+:\s+([0-9a-f]{64})$", text)
            if m:
                nonce = bytes.fromhex(m.group(1))
                ans = F(nonce).hex().encode() + b"\n"
                f.write(ans)
                continue

            if text.startswith("nope"):
                raise RuntimeError(text)

            if text.startswith("squ1rrel{"):
                return text


def main() -> None:
    flag = solve()
    print(flag)


if __name__ == "__main__":
    main()
