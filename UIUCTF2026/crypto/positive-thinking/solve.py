#!/usr/bin/env python3
import base64
import math
import os
import random
import re
import socket
import ssl
import sys
import time

HOST = os.environ.get("HOST", "positive-thinking.chal.uiuc.tf")
PORT = int(os.environ.get("PORT", "1337"))

SECRET_BITS = 50
MAX_SECRET = 2**SECRET_BITS - 1
MAX_QUERIES = 100
M = 2**49

# Guard kecil untuk jaga-jaga CKKS approximate di boundary.
GUARD = int(os.environ.get("GUARD", "8"))

FLAG_RE = re.compile(r"uiuctf\{[^}\n]+\}", re.I)

# T8 roots untuk x >= 0:
# cos(7pi/16), cos(5pi/16), cos(3pi/16), cos(pi/16)
R1 = math.cos(7 * math.pi / 16)
R2 = math.cos(5 * math.pi / 16)
R3 = math.cos(3 * math.pi / 16)
R4 = math.cos(1 * math.pi / 16)

A1 = math.floor(R1 * M)
B1_LO = math.ceil(R1 * M)
B1_HI = math.floor(R2 * M)

A2_LO = math.floor(R2 * M) + 1
A2_HI = math.ceil(R3 * M) - 1

B2_LO = math.ceil(R3 * M)
B2_HI = math.floor(R4 * M)

A3_LO = math.floor(R4 * M) + 1


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def die(msg):
    log(msg)
    raise SystemExit(1)


def recv_until_any(sock, markers, timeout=60):
    data = b""
    end = time.time() + timeout
    sock.setblocking(False)

    while time.time() < end:
        if any(m in data for m in markers):
            break

        try:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
        except (BlockingIOError, ssl.SSLWantReadError):
            time.sleep(0.02)

    sock.setblocking(True)
    return data


def parse_material(banner):
    text = banner.decode(errors="replace")
    lines = [line.strip() for line in text.splitlines()]

    ctx_b64 = None
    enc_b64 = None

    for i, line in enumerate(lines):
        if line == "Public context:":
            j = i + 1
            while j < len(lines) and not lines[j]:
                j += 1
            if j < len(lines):
                ctx_b64 = lines[j]

        elif line == "Encrypted value:":
            j = i + 1
            while j < len(lines) and not lines[j]:
                j += 1
            if j < len(lines):
                enc_b64 = lines[j]

    if not ctx_b64:
        die("[-] gagal parse Public context")

    if not enc_b64:
        die("[-] gagal parse Encrypted value")

    log(f"[+] parsed public context length: {len(ctx_b64)}")
    log(f"[+] parsed encrypted secret length: {len(enc_b64)}")

    return ctx_b64, enc_b64


def merge_intervals(intervals):
    intervals = sorted((int(l), int(r)) for l, r in intervals if l <= r)

    if not intervals:
        return []

    out = [list(intervals[0])]

    for l, r in intervals[1:]:
        if l <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], r)
        else:
            out.append([l, r])

    return [(l, r) for l, r in out]


def intersect_sets(a, b):
    a = merge_intervals(a)
    b = merge_intervals(b)

    i = 0
    j = 0
    out = []

    while i < len(a) and j < len(b):
        l = max(a[i][0], b[j][0])
        r = min(a[i][1], b[j][1])

        if l <= r:
            out.append((l, r))

        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1

    return merge_intervals(out)


def total_len(intervals):
    return sum(r - l + 1 for l, r in intervals)


def kth_value(intervals, k):
    intervals = merge_intervals(intervals)

    for l, r in intervals:
        n = r - l + 1

        if k < n:
            return l + k

        k -= n

    return intervals[-1][1]


def sign_sets_unamplified(center):
    """
    Untuk ciphertext = Enc(secret - center).

    Server ngecek:
        sign(T8((secret - center) / 2^49))

    T8 genap, jadi sign tergantung |secret - center|.
    """

    positive = [
        # |d| > root4
        (0, center - A3_LO),
        (center + A3_LO, MAX_SECRET),

        # root2 < |d| < root3
        (center - A2_HI, center - A2_LO),
        (center + A2_LO, center + A2_HI),

        # |d| < root1
        (center - A1, center + A1),
    ]

    negative = [
        # root1 < |d| < root2
        (center - B1_HI, center - B1_LO),
        (center + B1_LO, center + B1_HI),

        # root3 < |d| < root4
        (center - B2_HI, center - B2_LO),
        (center + B2_LO, center + B2_HI),
    ]

    positive = [(max(0, l), min(MAX_SECRET, r)) for l, r in positive]
    negative = [(max(0, l), min(MAX_SECRET, r)) for l, r in negative]

    return merge_intervals(positive), merge_intervals(negative)


def split_lengths(candidates, center):
    pos, neg = sign_sets_unamplified(center)
    return (
        total_len(intersect_sets(candidates, pos)),
        total_len(intersect_sets(candidates, neg)),
    )


def choose_center_unamplified(candidates):
    candidates = merge_intervals(candidates)
    total = total_len(candidates)

    trial = set()

    for q in range(1, 16):
        trial.add(kth_value(candidates, (total * q) // 16))

    thresholds = [
        A1,
        B1_LO,
        B1_HI,
        A2_LO,
        A2_HI,
        B2_LO,
        B2_HI,
        A3_LO,
    ]

    for l, r in candidates:
        for e in (l, r, (l + r) // 2):
            trial.add(e)

            for t in thresholds:
                trial.add(e - t)
                trial.add(e + t)
                trial.add(e - t - 1)
                trial.add(e + t + 1)

    rng = random.Random(0xA11CE + total.bit_length() + len(candidates))
    low = candidates[0][0] - A3_LO
    high = candidates[-1][1] + A3_LO

    for _ in range(150):
        trial.add(rng.randrange(low, high + 1))

    best = None

    for center in trial:
        pos_len, neg_len = split_lengths(candidates, center)

        if pos_len == 0 or neg_len == 0:
            continue

        worst = max(pos_len, neg_len)
        balance = abs(pos_len - neg_len)

        if best is None or (worst, balance) < (best[0], best[1]):
            best = (worst, balance, center)

    if best is None:
        die("[-] gagal pilih center unamplified")

    return int(best[2])


def choose_shift_for_interval(width):
    """
    Kita mau query:
        Enc( 2^shift * (secret - lo) )

    Selama:
        width * 2^shift < root2 * 2^49

    maka sign hanya punya 1 boundary awal:
        Positive kalau 2^shift * (secret - lo) <= root1 * 2^49
        Not positive kalau lebih dari itu.

    Jadi ini jadi comparison oracle yang monotonic.
    """

    best = None

    for shift in range(0, 80):
        mul = 1 << shift
        tau = A1 // mul

        if tau < 0 or tau >= width:
            continue

        if width * mul >= B1_HI:
            continue

        # Positive side: 0..tau
        # Negative side: tau+1..width
        pos_count = tau + 1
        neg_count = width - tau

        worst = max(pos_count, neg_count)
        balance = abs(pos_count - neg_count)

        if best is None or (worst, balance) < (best[0], best[1]):
            best = (worst, balance, shift, tau)

    if best is None:
        return None, None

    return best[2], best[3]


def make_ciphertext(enc_secret, base, shift):
    """
    Buat ciphertext:
        2^shift * (secret - base)

    PENTING:
    Ini pakai repeated addition, bukan scalar multiplication.
    Addition tidak mengonsumsi level CKKS seperti multiply/rescale.
    """

    ct = enc_secret - float(base)

    for _ in range(shift):
        ct = ct + ct

    return ct


def query_oracle(sock, ct_b64, guess):
    sock.sendall(ct_b64.encode() + b"\n")

    out1 = recv_until_any(
        sock,
        [b"Secret:", b"Invalid ciphertext"],
        timeout=120,
    )

    text1 = out1.decode(errors="replace")

    if "Invalid ciphertext" in text1:
        print(text1)
        die("[-] server bilang Invalid ciphertext")

    if "Not positive" in text1:
        positive = False
    elif "Positive" in text1:
        positive = True
    else:
        print(text1)
        die("[-] gagal baca Positive / Not positive")

    sock.sendall(str(guess).encode() + b"\n")

    out2 = recv_until_any(
        sock,
        [b"> ", b"uiuctf{", b"Maybe next time?"],
        timeout=120,
    )

    text = (out1 + out2).decode(errors="replace")
    return positive, text


def direct_guess(sock, enc_secret, lo, hi, used_queries):
    remaining = MAX_QUERIES - used_queries
    count = hi - lo + 1

    if count > remaining:
        return False

    log("[+] switching to direct guesses")
    log(f"[+] interval=[{lo}, {hi}], count={count}, remaining={remaining}")

    for i, guess in enumerate(range(lo, hi + 1), 1):
        log(f"[+] guess {i}/{count}: {guess}")

        ct = make_ciphertext(enc_secret, guess, 0)
        ct_b64 = base64.b64encode(ct.serialize()).decode()

        _, text = query_oracle(sock, ct_b64, guess)

        m = FLAG_RE.search(text)
        if m:
            print(text, end="" if text.endswith("\n") else "\n")
            print(f"\n<FLAG>{m.group(0)}</FLAG>")
            return True

    die("[-] direct guesses habis tapi flag tidak muncul")


def main():
    try:
        import tenseal as ts
    except Exception:
        die("[-] tenseal belum ada. Install dulu: pip install tenseal")

    log(f"[+] connecting to {HOST}:{PORT} over SSL")

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    raw = socket.create_connection((HOST, PORT), timeout=30)

    with raw:
        with ssl_ctx.wrap_socket(raw, server_hostname=HOST) as sock:
            banner = recv_until_any(sock, [b"> "], timeout=180)

            banner_text = banner.decode(errors="replace")
            if banner_text.splitlines():
                log(f"[+] {banner_text.splitlines()[0]}")

            ctx_b64, enc_b64 = parse_material(banner)

            public_context = ts.context_from(base64.b64decode(ctx_b64))
            enc_secret = ts.ckks_vector_from(
                public_context,
                base64.b64decode(enc_b64),
            )

            used_queries = 0
            candidates = [(0, MAX_SECRET)]

            log(f"[+] GUARD={GUARD}")
            log("[+] stage 1: unamplified narrowing")

            # Stage 1: pakai oracle asli sampai dapat 1 interval yang bisa
            # diproses sebagai monotonic amplified comparison.
            while True:
                candidates = merge_intervals(candidates)

                if len(candidates) == 1:
                    lo, hi = candidates[0]
                    width = hi - lo
                    shift, tau = choose_shift_for_interval(width)

                    if shift is not None:
                        log(f"[+] stage 1 done: interval=[{lo}, {hi}], width={width}")
                        break

                if used_queries >= 25:
                    die(f"[-] stage 1 terlalu lama, candidates={candidates[:10]}")

                center = choose_center_unamplified(candidates)
                ct = make_ciphertext(enc_secret, center, 0)
                ct_b64 = base64.b64encode(ct.serialize()).decode()

                used_queries += 1
                positive, text = query_oracle(sock, ct_b64, -1)

                pos, neg = sign_sets_unamplified(center)
                candidates = intersect_sets(candidates, pos if positive else neg)

                if not candidates:
                    die("[-] candidates kosong di stage 1")

                log(
                    f"[+] stage1 round {used_queries:02d}: "
                    f"{'Positive' if positive else 'Not positive'} | "
                    f"total={total_len(candidates)} | intervals={len(candidates)}"
                )

                m = FLAG_RE.search(text)
                if m:
                    print(f"\n<FLAG>{m.group(0)}</FLAG>")
                    return

            # Stage 2: amplified monotonic comparison.
            log("[+] stage 2: amplified monotonic narrowing")

            while used_queries < MAX_QUERIES:
                lo, hi = candidates[0]

                if direct_guess(sock, enc_secret, lo, hi, used_queries):
                    return

                width = hi - lo
                shift, tau = choose_shift_for_interval(width)

                if shift is None:
                    die(f"[-] tidak bisa pilih shift untuk width={width}")

                ct = make_ciphertext(enc_secret, lo, shift)
                ct_b64 = base64.b64encode(ct.serialize()).decode()

                used_queries += 1
                positive, text = query_oracle(sock, ct_b64, -1)

                boundary = lo + tau

                if positive:
                    # Ideal: secret <= boundary
                    # Tambahkan guard karena CKKS approximate.
                    hi = min(hi, boundary + GUARD)
                else:
                    # Ideal: secret > boundary
                    # Tambahkan guard ke kiri.
                    lo = max(lo, boundary + 1 - GUARD)

                candidates = [(lo, hi)]

                log(
                    f"[+] stage2 round {used_queries:02d}: "
                    f"shift={shift} tau={tau} "
                    f"{'Positive' if positive else 'Not positive'} | "
                    f"interval=[{lo}, {hi}] size={hi - lo + 1}"
                )

                m = FLAG_RE.search(text)
                if m:
                    print(f"\n<FLAG>{m.group(0)}</FLAG>")
                    return

            die("[-] query habis")


if __name__ == "__main__":
    main()
