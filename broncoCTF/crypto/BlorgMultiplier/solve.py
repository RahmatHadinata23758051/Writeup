#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import re
import sys

from pwn import context, remote


# Classic 128-byte MD5 collision pair.
# Both byte strings hash to:
#   79054025255fb1a26e4bc422aef54eb4
#
# They contain no LF byte, so they can be submitted through input().
COLLISION_A = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c"
    "2fcab58712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e488832571415a"
    "085125e8f7cdc99fd91dbdf280373c5b"
    "d8823e3156348f5bae6dacd436c919c6"
    "dd53e2b487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080a80d1e"
    "c69821bcb6a8839396f9652b6ff72a70"
)

COLLISION_B = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c"
    "2fcab50712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e4888325f1415a"
    "085125e8f7cdc99fd91dbd7280373c5b"
    "d8823e3156348f5bae6dacd436c919c6"
    "dd53e23487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080280d1e"
    "c69821bcb6a8839396f965ab6ff72a70"
)

FLAG_RE = re.compile(rb"bronco\{[^}\r\n]+\}")


def to_wire(raw: bytes) -> bytes:
    """
    Remote input() decodes UTF-8, then the challenge re-encodes with latin-1.

    Mapping arbitrary collision bytes through latin-1 -> UTF-8 makes the
    challenge recover the exact original byte sequence before hashing.
    """
    return raw.decode("latin-1").encode("utf-8")


def validate_collision() -> None:
    digest_a = hashlib.md5(COLLISION_A).hexdigest()
    digest_b = hashlib.md5(COLLISION_B).hexdigest()

    if COLLISION_A == COLLISION_B:
        raise RuntimeError("Collision blocks unexpectedly identical")
    if digest_a != digest_b:
        raise RuntimeError("Embedded MD5 collision pair is invalid")
    if b"\n" in COLLISION_A or b"\n" in COLLISION_B:
        raise RuntimeError("Collision block contains LF and cannot use input()")


def send_command(io, command: bytes) -> None:
    io.sendlineafter(b"> ", command)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Solve BroncoCTF Blorg Multiplier"
    )
    parser.add_argument(
        "host",
        nargs="?",
        default="0.cloud.chals.io",
        help="remote host",
    )
    parser.add_argument(
        "port",
        nargs="?",
        type=int,
        default=13758,
        help="remote port",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="enable pwntools debug logging",
    )
    args = parser.parse_args()

    validate_collision()
    context.log_level = "debug" if args.debug else "error"

    io = remote(args.host, args.port)

    # Register COLLISION_A as the custom command name.
    send_command(io, b"program")
    io.sendlineafter(
        b"What is the name of the new command? ",
        to_wire(COLLISION_A),
    )

    # The command body is irrelevant because COLLISION_A is never invoked.
    io.sendlineafter(
        b"Which (space separated) commands would you like it to run:",
        b"none",
    )

    # Reach exactly 468 with only three edits:
    #
    # 1 -> 2 -> 4 -> 8 -> 16
    #   decrease -> 30
    #   none     -> 60
    #   decrease -> 118
    #   decrease -> 234
    #   none     -> 468
    sequence = [
        b"none",
        b"none",
        b"none",
        b"none",
        b"decrease",
        b"none",
        b"decrease",
        b"decrease",
        b"none",
    ]

    for command in sequence:
        send_command(io, command)

    # COLLISION_B has the same MD5 as the registered program command, so it
    # passes the whitelist. It is not equal to COLLISION_A, therefore it skips
    # the `user_in == program` branch and falls into the flag-checking `else`.
    send_command(io, to_wire(COLLISION_B))

    data = io.recvrepeat(3)
    match = FLAG_RE.search(data)

    if match is None:
        print(data.decode("utf-8", errors="replace"))
        raise RuntimeError("Flag tidak ditemukan pada response remote")

    flag = match.group(0).decode("ascii")
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    try:
        main()
    except (EOFError, OSError, RuntimeError) as error:
        print(f"[-] {error}", file=sys.stderr)
        raise SystemExit(1)
