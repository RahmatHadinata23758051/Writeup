#!/usr/bin/env python3
import argparse
import os
import socket
import struct
import subprocess
import sys
from typing import Iterable, List, Tuple

Term = Tuple[int, int, int, float]

# The program asks for 3 sparse polynomials F=(a,b,c) over Q[x,y,z],
# then two different points P,Q with F(P)=F(Q), while det(J_F) is a non-zero constant.
# This is the compact expanded form of the Alpoge/Fable 3-variable Jacobian map:
#
# a = (1+xy)^3 z + y^2(1+xy)(4+3xy)
# b = y + 3x(1+xy)^2 z + 3xy^2(4+3xy)
# c = 2x - 3x^2 y - x^3 z
#
# det(J_F) = -2, and both points below map to (-1/4, 0, 0).
POLYS: List[List[Term]] = [
    [
        (0, 0, 1, 1.0),
        (1, 1, 1, 3.0),
        (2, 2, 1, 3.0),
        (3, 3, 1, 1.0),
        (0, 2, 0, 4.0),
        (1, 3, 0, 7.0),
        (2, 4, 0, 3.0),
    ],
    [
        (0, 1, 0, 1.0),
        (1, 0, 1, 3.0),
        (2, 1, 1, 6.0),
        (3, 2, 1, 3.0),
        (1, 2, 0, 12.0),
        (2, 3, 0, 9.0),
    ],
    [
        (1, 0, 0, 2.0),
        (2, 1, 0, -3.0),
        (3, 0, 1, -1.0),
    ],
]

POINTS = (
    0.0, 0.0, -0.25,   # P = (0, 0, -1/4)
    1.0, -1.5, 6.5,    # Q = (1, -3/2, 13/2)
)


def build_payload() -> bytes:
    payload = bytearray()

    for poly in POLYS:
        if len(poly) > 0x1000:
            raise ValueError("too many terms")
        payload += struct.pack("<H", len(poly))

        for x_exp, y_exp, z_exp, coeff in poly:
            if not (0 <= x_exp <= 60 and 0 <= y_exp <= 60 and 0 <= z_exp <= 60):
                raise ValueError("exponent out of range")
            if x_exp + y_exp + z_exp > 120:
                raise ValueError("total degree out of range")
            payload += bytes((x_exp, y_exp, z_exp))
            payload += struct.pack("<d", coeff)

    payload += struct.pack("<6d", *POINTS)
    return bytes(payload)


def run_local(binary: str, payload: bytes) -> int:
    env = os.environ.copy()
    env.setdefault("FLAG", "LOCAL_ACCEPTED")
    proc = subprocess.run(
        [binary],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=5,
    )
    sys.stdout.buffer.write(proc.stdout)
    sys.stderr.buffer.write(proc.stderr)
    return proc.returncode


def send_remote(host: str, port: int, payload: bytes) -> int:
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(payload)
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass

        chunks = []
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)

    sys.stdout.buffer.write(b"".join(chunks))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Solver for Rivers")
    parser.add_argument("host", nargs="?", help="remote host")
    parser.add_argument("port", nargs="?", type=int, help="remote port")
    parser.add_argument("--binary", default=None, help="run payload against local binary")
    parser.add_argument("--output", "-o", default=None, help="write raw payload to file")
    args = parser.parse_args()

    payload = build_payload()

    if args.output:
        with open(args.output, "wb") as f:
            f.write(payload)
        print(f"[+] wrote {len(payload)} bytes to {args.output}", file=sys.stderr)

    if args.host and args.port:
        return send_remote(args.host, args.port, payload)

    if args.binary:
        return run_local(args.binary, payload)

    if not args.output:
        # Useful for: python3 solve.py | nc HOST PORT
        sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
