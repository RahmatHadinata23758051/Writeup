#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
import multiprocessing as mp
import os
import socket
import sys
from typing import Iterable

from Crypto.Cipher import AES

KDF_INFO = b"lyknctf-2026"
DENSITY = 0.36
FLAG_PREFIXES = (b"LYKN{", b"LYKNCTF{")
G = {}


def extract_json(data: bytes):
    """Return (object, end_offset) for the first complete JSON object in data."""
    text = data.decode(errors="ignore")
    starts = [i for i, ch in enumerate(text) if ch == "{"]
    for start in starts:
        depth = 0
        in_string = False
        escaped = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start : i + 1]
                    try:
                        return json.loads(candidate), i + 1
                    except json.JSONDecodeError:
                        break
    return None, None


def sign_counts(target_even: int, target_odd: int, N: int):
    """Exact +/- coefficient counts produced by constrained_ternary()."""
    used = abs(target_even) + abs(target_odd)
    target_total = int(DENSITY * N)
    pad_needed = max(target_total - used, 0)
    pairs_per_parity = pad_needed // 4 + 1

    positive = max(target_even, 0) + max(target_odd, 0) + 2 * pairs_per_parity
    negative = max(-target_even, 0) + max(-target_odd, 0) + 2 * pairs_per_parity
    return positive, negative


def residue_intervals(lo: int, hi: int, modulus: int):
    """Convert every integer in [lo, hi] into compact residue intervals mod modulus."""
    if hi - lo + 1 >= modulus:
        return [(0, modulus)]

    pieces = []
    first_k = lo // modulus
    last_k = hi // modulus
    for k in range(first_k, last_k + 1):
        left = max(lo, k * modulus)
        right = min(hi, (k + 1) * modulus - 1)
        if left <= right:
            pieces.append((left - k * modulus, right - k * modulus + 1))

    merged = []
    for left, right in sorted(pieces):
        if merged and left <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], right))
        else:
            merged.append((left, right))
    return merged


def candidate_intervals(instance: dict):
    params = instance["parameters"]
    leak = instance["leakage"]
    N = int(params["N"])
    q_prime = int(params["q_prime"])

    fp, fn = sign_counts(int(leak["f_even_sum"]), int(leak["f_odd_sum"]), N)
    gp, gn = sign_counts(int(leak["g_even_sum"]), int(leak["g_odd_sum"]), N)

    positive_products = fp * gp + fn * gn
    negative_products = fp * gn + fn * gp

    # Every pair f_i*g_j contributes once to weighted_trace with weight 1..N.
    lo = positive_products - N * negative_products
    hi = N * positive_products - negative_products
    return residue_intervals(lo, hi, q_prime), (lo, hi)


def init_worker(instance: dict):
    params = instance["parameters"]
    enc = instance["encrypted_flag"]
    N = int(params["N"])
    q = int(params["q"])
    q_prime = int(params["q_prime"])

    G.clear()
    G.update(
        salt=str(N).encode(),
        info=KDF_INFO,
        ikm_suffix=(
            N.to_bytes(2, "big")
            + q.to_bytes(2, "big")
            + q_prime.to_bytes(4, "big")
        ),
        nonce=bytes.fromhex(enc["nonce"]),
        ciphertext=bytes.fromhex(enc["ciphertext"]),
        tag=bytes.fromhex(enc["tag"]),
    )


def derive_key(s_alg: int):
    ikm = s_alg.to_bytes(4, "big") + G["ikm_suffix"]
    prk = hmac.digest(G["salt"], ikm, "sha256")
    return hmac.digest(prk, G["info"] + b"\x01", "sha256")


def test_chunk(bounds):
    start, stop = bounds
    nonce = G["nonce"]
    ciphertext = G["ciphertext"]
    tag = G["tag"]
    head_len = min(8, len(ciphertext))

    for s_alg in range(start, stop):
        key = derive_key(s_alg)

        # Prefix test avoids the expensive GHASH/tag check for almost all keys.
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        head = cipher.decrypt(ciphertext[:head_len])
        if not head.startswith(FLAG_PREFIXES):
            continue

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            continue
        return s_alg, plaintext
    return None


def make_chunks(intervals: Iterable[tuple[int, int]], chunk_size: int):
    for start, stop in intervals:
        for left in range(start, stop, chunk_size):
            yield left, min(left + chunk_size, stop)


def solve_instance(instance: dict, workers: int, chunk_size: int = 2048):
    intervals, raw_bound = candidate_intervals(instance)
    total = sum(stop - start for start, stop in intervals)
    print(f"[*] weighted integer bound: {raw_bound[0]} .. {raw_bound[1]}", file=sys.stderr)
    print(f"[*] candidate residues: {total} / {instance['parameters']['q_prime']}", file=sys.stderr)
    print(f"[*] workers: {workers}", file=sys.stderr)

    chunks = list(make_chunks(intervals, chunk_size))
    ctx = mp.get_context("fork")
    with ctx.Pool(workers, initializer=init_worker, initargs=(instance,)) as pool:
        for result in pool.imap_unordered(test_chunk, chunks, chunksize=1):
            if result is not None:
                pool.terminate()
                pool.join()
                return result
    raise RuntimeError("no valid AES-GCM key found")


def load_instance_from_file(path: str):
    with open(path, "rb") as handle:
        data = handle.read()
    obj, _ = extract_json(data)
    if obj is None:
        raise ValueError(f"no JSON object found in {path}")
    return obj


def receive_instance(sock: socket.socket):
    data = bytearray()
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            raise EOFError("remote closed before sending a complete JSON instance")
        data.extend(chunk)
        sys.stderr.buffer.write(chunk)
        sys.stderr.buffer.flush()
        obj, _ = extract_json(bytes(data))
        if obj is not None:
            return obj


def main():
    parser = argparse.ArgumentParser(description="Sleepless Machine solver")
    parser.add_argument("target", nargs="?", help="instance JSON file, or remote host")
    parser.add_argument("port", nargs="?", type=int, help="remote port")
    parser.add_argument(
        "-j",
        "--workers",
        type=int,
        default=min(16, os.cpu_count() or 1),
        help="number of brute-force workers (default: min(16, CPU count))",
    )
    parser.add_argument("--chunk-size", type=int, default=2048)
    args = parser.parse_args()

    if not args.target:
        raw = sys.stdin.buffer.read()
        instance, _ = extract_json(raw)
        if instance is None:
            parser.error("provide HOST PORT, an instance JSON file, or JSON on stdin")
        remote = None
    elif args.port is None:
        instance = load_instance_from_file(args.target)
        remote = None
    else:
        remote = socket.create_connection((args.target, args.port))
        instance = receive_instance(remote)

    s_alg, plaintext = solve_instance(instance, max(1, args.workers), args.chunk_size)
    flag = plaintext.decode()
    print(f"[+] s_alg = {s_alg}")
    print(f"<FLAG>{flag}</FLAG>")

    if remote is not None:
        remote.sendall(plaintext + b"\n")
        remote.settimeout(2.0)
        try:
            while True:
                chunk = remote.recv(65536)
                if not chunk:
                    break
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
        except (socket.timeout, TimeoutError):
            pass
        finally:
            remote.close()


if __name__ == "__main__":
    main()
