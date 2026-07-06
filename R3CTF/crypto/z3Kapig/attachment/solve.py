#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import math
import multiprocessing as mp
import os
import queue
import secrets
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from functools import reduce
from typing import Optional

import gmpy2
from Crypto.Util.number import getPrime

from crypto.common.ec import ECOperations, Point
from crypto.common.paillier import (
    PrivateKey,
    PublicKey,
    get_random_positive_relatively_prime_int,
)
from crypto.common.numbers import rejection_sample
from crypto.zkp.affg import ProofAffg
from crypto.zkp.enc import ProofEnc
from crypto.zkp.fac import ProofFac
from crypto.zkp.hash import sha512_256i
from crypto.zkp.hv import ProofST, second_base_point
from crypto.zkp.logstar import ProofLogstar
from crypto.zkp.mod import ProofMod
from crypto.zkp.prm import ProofPrm
from crypto.zkp.sch import ProofSch
from ecdsa.messages import (
    AuxRound1Message,
    AuxRound2Message,
    AuxRound3Message,
    KeygenRound1Message,
    KeygenRound2Message,
    KeygenRound3Message,
    PresigningRound1Message,
    PresigningRound2Message,
    PresigningRound3Message,
    SigningMessage,
)
from ecdsa.small_primes import SMALL_PRIMES


EC = ECOperations()
Q = int(EC.n)
INF = Point.infinity(EC.curve)
MOD_BITS = 2048
MOD_PROOF_ITERS = 80


def log(msg: str) -> None:
    print(msg, flush=True)


def point_neg(p: Point) -> Point:
    if p.is_infinity:
        return INF
    return Point(p.x, (-p.y) % EC.p, EC.curve)


def point_sub(a: Point, b: Point) -> Point:
    return EC.point_add(a, point_neg(b))


def point_key(p: Point) -> tuple[int, int]:
    if p.is_infinity:
        return (0, 0)
    return (int(p.x), int(p.y))


def bsgs_bounded(base: Point, target: Point, bound: int) -> Optional[int]:
    """Solve target = x*base for 0 <= x < bound."""
    if bound <= 0:
        return None
    m = math.isqrt(bound) + 1
    baby: dict[tuple[int, int], int] = {}
    cur = INF
    for j in range(m):
        baby.setdefault(point_key(cur), j)
        cur = EC.point_add(cur, base)

    giant = point_neg(EC.scalar_mult(m, base))
    cur = target
    for i in range((bound + m - 1) // m + 1):
        j = baby.get(point_key(cur))
        if j is not None:
            x = i * m + j
            if x < bound and EC.scalar_mult(x, base) == target:
                return x
        cur = EC.point_add(cur, giant)
    return None


def signed_small_dlog(base: Point, target: Point, prime: int) -> int:
    """Solve target = z*base for -prime <= z < prime."""
    z = bsgs_bounded(base, target, prime)
    if z is not None:
        return z
    z = bsgs_bounded(base, point_neg(target), prime + 1)
    if z is None:
        raise RuntimeError("small discrete log was not found")
    return -z


def crt_pairwise(residues: list[int], moduli: list[int]) -> int:
    x = 0
    modulus = 1
    for residue, p in zip(residues, moduli):
        step = ((residue - x) * pow(modulus, -1, p)) % p
        x += step * modulus
        modulus *= p
    return x % modulus


class Tube:
    def sendline(self, data: bytes) -> None:
        raise NotImplementedError

    def recvline(self) -> bytes:
        raise NotImplementedError

    def close(self) -> None:
        pass


class SocketTube(Tube):
    def __init__(self, host: str, port: int):
        self.sock = socket.create_connection((host, port), timeout=30)
        self.sock.settimeout(None)
        self.file = self.sock.makefile("rwb", buffering=0)

    def sendline(self, data: bytes) -> None:
        self.file.write(data + b"\n")

    def recvline(self) -> bytes:
        line = self.file.readline()
        if not line:
            raise EOFError("remote closed the connection")
        return line

    def close(self) -> None:
        try:
            self.file.close()
        finally:
            self.sock.close()


class ProcessTube(Tube):
    def __init__(self, timeout: int):
        env = os.environ.copy()
        env["POW_DIFFICULTY"] = "0"
        env["PROTOCOL_TIMEOUT_SECONDS"] = str(timeout)
        self.proc = subprocess.Popen(
            [sys.executable, "main.py"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            env=env,
        )
        assert self.proc.stdin is not None and self.proc.stdout is not None

    def sendline(self, data: bytes) -> None:
        self.proc.stdin.write(data + b"\n")
        self.proc.stdin.flush()

    def recvline(self) -> bytes:
        assert self.proc.stdout is not None
        line = self.proc.stdout.readline()
        if not line:
            raise EOFError("local server exited")
        return line

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()


class Client:
    def __init__(self, tube: Tube, verbose: bool = False):
        self.tube = tube
        self.verbose = verbose

    def recv_json(self) -> dict:
        while True:
            raw = self.tube.recvline().decode(errors="replace").strip()
            if not raw:
                continue
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                if self.verbose:
                    log(f"[server] {raw}")

    def send_json(self, obj: dict) -> None:
        if self.verbose:
            log(f"[send] phase={obj.get('phase')} action={obj.get('action')}")
        self.tube.sendline(json.dumps(obj, separators=(",", ":")).encode())

    def command(self, phase: int, action: str, data: Optional[dict] = None) -> dict:
        obj = {"phase": phase, "action": action}
        if data is not None:
            obj["data"] = data
        self.send_json(obj)
        response = self.recv_json()
        if response.get("status") != "ok":
            raise RuntimeError(json.dumps(response, indent=2))
        return response.get("result")

    def guess(self, x: int) -> dict:
        self.send_json({"phase": 0, "action": "guess_key", "data": {"guess": int(x)}})
        response = self.recv_json()
        if response.get("status") != "ok":
            raise RuntimeError(json.dumps(response, indent=2))
        return response["result"]


# ------------------------- PoW -------------------------

def _zero_bits_ok(digest: bytes, difficulty: int) -> bool:
    full, rem = divmod(difficulty, 8)
    if any(digest[:full]):
        return False
    return rem == 0 or digest[full] >> (8 - rem) == 0


def _pow_worker(challenge: bytes, difficulty: int, start: int, stride: int, event, outq) -> None:
    prefix = hashlib.sha256(challenge)
    nonce = start
    checks = 0
    while nonce < (1 << 64):
        h = prefix.copy()
        h.update(nonce.to_bytes(8, "big"))
        if _zero_bits_ok(h.digest(), difficulty):
            if not event.is_set():
                outq.put(nonce)
                event.set()
            return
        nonce += stride
        checks += 1
        if checks & 0x3FFF == 0 and event.is_set():
            return


def solve_pow_parallel(challenge: bytes, difficulty: int, workers: int) -> int:
    if difficulty == 0:
        return 0
    workers = max(1, workers)
    if workers == 1:
        prefix = hashlib.sha256(challenge)
        for nonce in range(1 << 64):
            h = prefix.copy()
            h.update(nonce.to_bytes(8, "big"))
            if _zero_bits_ok(h.digest(), difficulty):
                return nonce
        raise RuntimeError("PoW exhausted")

    ctx = mp.get_context("fork")
    event = ctx.Event()
    outq = ctx.Queue()
    procs = [
        ctx.Process(
            target=_pow_worker,
            args=(challenge, difficulty, i, workers, event, outq),
        )
        for i in range(workers)
    ]
    for p in procs:
        p.start()
    try:
        nonce = outq.get()
    finally:
        event.set()
        for p in procs:
            p.join(timeout=0.2)
            if p.is_alive():
                p.terminate()
        for p in procs:
            p.join()
    return int(nonce)


# ------------------- malicious Paillier -------------------

@dataclass
class MaliciousPaillier:
    small_primes: list[int]
    factors: list[int]
    Wbase: int
    remaining_prime: int
    N: int
    phi: int
    lam_n: int
    priv: PrivateKey
    pub: PublicKey
    prm_lambda: int = 0
    s: int = 0
    t: int = 0
    rho_aux: int = 0
    prm: Optional[ProofPrm] = None


def build_malicious_paillier() -> MaliciousPaillier:
    small: list[int] = []
    x = int(SMALL_PRIMES[-1])
    while len(small) < 15:
        x = int(gmpy2.next_prime(x))
        small.append(x)

    small_product = math.prod(small)
    if small_product <= Q:
        raise RuntimeError("not enough CRT primes")

    while True:
        medium = getPrime(753)
        Wbase = small_product * medium
        remaining_bits = MOD_BITS - Wbase.bit_length() + 1
        if remaining_bits < 1000:
            continue
        while True:
            remaining = getPrime(remaining_bits)
            if remaining % 4 == 3:
                break
        factors = small + [medium, remaining]
        N = Wbase * remaining
        if N.bit_length() != MOD_BITS:
            continue
        lam_n = 1
        phi = 1
        for f in factors:
            lam_n = int(gmpy2.lcm(lam_n, f - 1))
            phi *= f - 1
        if math.gcd(N, lam_n) != 1 or math.gcd(N, phi) != 1:
            continue
        priv = PrivateKey(N, lam_n, phi)
        priv.cache_lg_inv()
        return MaliciousPaillier(
            small_primes=small,
            factors=factors,
            Wbase=Wbase,
            remaining_prime=remaining,
            N=N,
            phi=phi,
            lam_n=lam_n,
            priv=priv,
            pub=PublicKey(N),
        )


def prepare_prm(mal: MaliciousPaillier, ssid: int) -> None:
    while True:
        r = int(get_random_positive_relatively_prime_int(mal.N))
        t = pow(r, 2, mal.N)
        lam = secrets.randbelow(mal.phi - 1) + 1
        s = pow(t, lam, mal.N)
        if 1 < s < mal.N and 1 < t < mal.N and s != t:
            break
    mal.prm_lambda = lam
    mal.s = s
    mal.t = t
    mal.rho_aux = secrets.randbelow(mal.N - 1) + 1
    mal.prm = ProofPrm.new_proof(ssid, s, t, mal.N, mal.phi, lam)
    if not mal.prm.verify(ssid, s, t, mal.N):
        raise RuntimeError("internal Prm proof failure")


def forge_mod_proof(seed: int, mal: MaliciousPaillier) -> ProofMod:
    N = mal.N
    Wbase = mal.Wbase
    rprime = mal.remaining_prime
    inv_n = pow(N, -1, mal.lam_n)
    inv_four = pow(4, -1, (rprime - 1) // 2)
    inv_wbase = pow(Wbase, -1, rprime)

    while True:
        c = secrets.randbelow(rprime - 1) + 1
        W = Wbase * c
        ys: list[int] = []
        valid = True
        for i in range(MOD_PROOF_ITERS):
            y = sha512_256i(seed, W, N, *ys) % N
            if y == 0 or math.gcd(y, N) != 1:
                valid = False
                break
            ys.append(y)
        if valid:
            break

    xs: list[int] = []
    zs: list[int] = []
    A = 0xFF
    B = 0xFF
    for y in ys:
        wy = (W % rprime) * (y % rprime) % rprime
        if pow(wy, (rprime - 1) // 2, rprime) == 1:
            a = 0
            rhs = wy
        else:
            a = 1
            rhs = (-wy) % rprime
        xr = pow(rhs, inv_four, rprime)
        xcrt = Wbase * ((xr * inv_wbase) % rprime)
        z = pow(y, inv_n, N)
        if not (0 < xcrt < N and 0 < z < N):
            raise RuntimeError("bad Mod proof root")
        xs.append(xcrt)
        zs.append(z)
        A = (A << 8) | a
        B = (B << 8) | 1

    proof = ProofMod(W, xs, A, B, zs)
    if not proof.verify(seed, N):
        raise RuntimeError("internal Mod proof failure")
    return proof


# ------------------- fast proof grinding -------------------

def _signed_int_bytes(i: int) -> bytes:
    i = int(i)
    mag = abs(i).to_bytes((abs(i).bit_length() + 7) // 8, "big") if i else b""
    sign = 1 if i > 0 else 0xFF if i < 0 else 0
    return mag + bytes([sign])


def _hash_item(i: int) -> bytes:
    b = _signed_int_bytes(i)
    return b + b"$" + struct.pack("<Q", len(b))


def _hash_split(fields: list[int], variable_index: int) -> tuple[bytes, bytes]:
    prefix = struct.pack("<Q", len(fields))
    prefix += b"".join(_hash_item(x) for x in fields[:variable_index])
    suffix = b"".join(_hash_item(x) for x in fields[variable_index + 1 :])
    return prefix, suffix


def _grind_worker(
    prefix: bytes,
    suffix: bytes,
    commit0: int,
    multiplier_base: int,
    modulus: int,
    prime: int,
    curve_q: int,
    gamma0: int,
    worker_index: int,
    worker_count: int,
    max_steps: int,
    event,
    outq,
) -> None:
    commit = (commit0 * pow(multiplier_base, worker_index, modulus)) % modulus
    gamma = gamma0 + worker_index
    jump = pow(multiplier_base, worker_count, modulus)
    for step in range(max_steps):
        b = _signed_int_bytes(commit)
        data = prefix + b + b"$" + struct.pack("<Q", len(b)) + suffix
        e = int.from_bytes(hashlib.new("sha512_256", data).digest(), "big") % curve_q
        if e % prime == 0:
            if not event.is_set():
                outq.put((gamma, commit, e, worker_index + step * worker_count))
                event.set()
            return
        commit = (commit * jump) % modulus
        gamma += worker_count
        if step & 0x3FF == 0 and event.is_set():
            return


def grind_commitment(
    fields: list[int],
    variable_index: int,
    commit0: int,
    multiplier: int,
    modulus: int,
    prime: int,
    gamma0: int,
    workers: int,
) -> tuple[int, int, int, int]:
    prefix, suffix = _hash_split(fields, variable_index)
    workers = max(1, workers)
    if workers == 1:
        commit = commit0
        gamma = gamma0
        for count in range(prime * 80):
            b = _signed_int_bytes(commit)
            data = prefix + b + b"$" + struct.pack("<Q", len(b)) + suffix
            e = int.from_bytes(hashlib.new("sha512_256", data).digest(), "big") % Q
            if e % prime == 0:
                return gamma, commit, e, count
            commit = (commit * multiplier) % modulus
            gamma += 1
        raise RuntimeError("proof grind exhausted")

    ctx = mp.get_context("fork")
    event = ctx.Event()
    outq = ctx.Queue()
    max_steps = (prime * 80 + workers - 1) // workers
    procs = [
        ctx.Process(
            target=_grind_worker,
            args=(
                prefix,
                suffix,
                commit0,
                multiplier,
                modulus,
                prime,
                Q,
                gamma0,
                i,
                workers,
                max_steps,
                event,
                outq,
            ),
        )
        for i in range(workers)
    ]
    for proc in procs:
        proc.start()
    try:
        result = outq.get(timeout=180)
    except queue.Empty as exc:
        raise RuntimeError("proof grind timed out") from exc
    finally:
        event.set()
        for proc in procs:
            proc.join(timeout=0.2)
            if proc.is_alive():
                proc.terminate()
        for proc in procs:
            proc.join()
    return tuple(map(int, result))


def random_unit(n: int) -> int:
    return int(get_random_positive_relatively_prime_int(n))


def forge_enc(
    ssid: int,
    pk: PublicKey,
    K: int,
    rho: int,
    Ncap: int,
    s: int,
    t: int,
    prime: int,
    workers: int,
) -> ProofEnc:
    N = int(pk.n)
    Nsq = int(pk.n_square)
    q2 = Q * Q
    q3 = q2 * Q
    alpha = secrets.randbelow(q3 - q2 - 1) + 1
    mu = secrets.randbelow(Q * Ncap)
    gamma0 = secrets.randbelow(q3 * Ncap)
    r = random_unit(N)

    S = pow(s, Q, Ncap) * pow(t, mu, Ncap) % Ncap
    A = pow(int(pk.gamma), alpha, Nsq) * pow(r, N, Nsq) % Nsq
    C0 = pow(s, alpha, Ncap) * pow(t, gamma0, Ncap) % Ncap

    fields = [
        ssid,
        N,
        int(pk.gamma),
        int(EC.curve.b),
        Q,
        int(EC.p),
        Ncap,
        s,
        t,
        K,
        S,
        A,
        C0,
    ]
    gamma, C, e, attempts = grind_commitment(
        fields, 12, C0, t, Ncap, prime, gamma0, workers
    )
    z1 = e * Q + alpha
    z2 = pow(rho, e, N) * r % N
    z3 = e * mu + gamma
    proof = ProofEnc(S, A, C, z1, z2, z3)
    if not proof.verify(ssid, EC, pk, Ncap, s, t, K):
        raise RuntimeError("internal forged Enc proof failure")
    log(f"    forged Enc after {attempts + 1:,} hashes")
    return proof


def forge_logstar(
    ssid: int,
    pk: PublicKey,
    C_cipher: int,
    rho: int,
    X: Point,
    base: Point,
    Ncap: int,
    s: int,
    t: int,
    prime: int,
    workers: int,
) -> ProofLogstar:
    N = int(pk.n)
    Nsq = int(pk.n_square)
    q2 = Q * Q
    q3 = q2 * Q
    alpha = secrets.randbelow(q3 - q2 - 1) + 1
    mu = secrets.randbelow(Q * Ncap)
    gamma0 = secrets.randbelow(q3 * Ncap)
    r = random_unit(N)

    S = pow(s, Q, Ncap) * pow(t, mu, Ncap) % Ncap
    A = pow(int(pk.gamma), alpha, Nsq) * pow(r, N, Nsq) % Nsq
    Y = EC.scalar_mult(alpha % Q, base)
    D0 = pow(s, alpha, Ncap) * pow(t, gamma0, Ncap) % Ncap

    fields = [
        ssid,
        N,
        int(pk.gamma),
        int(EC.curve.b),
        Q,
        int(EC.p),
        C_cipher,
        int(X.x),
        int(X.y),
        int(base.x),
        int(base.y),
        S,
        A,
        int(Y.x),
        int(Y.y),
        D0,
        Ncap,
        s,
        t,
    ]
    gamma, D, e, attempts = grind_commitment(
        fields, 15, D0, t, Ncap, prime, gamma0, workers
    )
    z1 = e * Q + alpha
    z2 = pow(rho, e, N) * r % N
    z3 = e * mu + gamma
    proof = ProofLogstar(S, A, Y, D, z1, z2, z3)
    if not proof.verify(ssid, EC, pk, C_cipher, X, base, Ncap, s, t):
        raise RuntimeError("internal forged Logstar proof failure")
    log(f"    forged Logstar after {attempts + 1:,} hashes")
    return proof


# ------------------------ protocol ------------------------

def perform_keygen(client: Client) -> tuple[int, Point]:
    log("[1/3] key generation")
    client.command(1, "start_phase")
    server_r1 = KeygenRound1Message.from_dict(client.command(1, "round1"))

    rid = secrets.randbits(256)
    alpha = EC.random_scalar()
    A = EC.scalar_mult(alpha)
    X = INF
    V = sha512_256i(0, rid, X.x, X.y, A.x, A.y)
    our_r1 = KeygenRound1Message(id=0, V=V)

    server_r2 = KeygenRound2Message.from_dict(
        client.command(1, "round2", our_r1.to_dict())
    )
    ssid = rid ^ int(server_r2.rid)

    our_r2 = KeygenRound2Message(rid=rid, X=X, A=A)
    client.command(1, "round3", our_r2.to_dict())

    sch_x = ProofSch.new_proof_with_alpha(ssid, EC, X, A, alpha, Q)
    sch_a = ProofSch.new_proof(ssid, EC, A, alpha)
    psi = sha512_256i(
        0,
        ssid,
        sch_x.A.x,
        sch_x.A.y,
        sch_x.Z,
        sch_a.A.x,
        sch_a.A.y,
        sch_a.Z,
    )
    our_r3 = KeygenRound3Message(
        schX=sch_x.to_bytes_parts(), schA=sch_a.to_bytes_parts(), psi=psi
    )
    client.command(1, "round_out", our_r3.to_dict())
    Xi = server_r2.X
    return ssid, Xi


def perform_aux(client: Client, ssid: int, mal: MaliciousPaillier) -> tuple[PublicKey, int, int]:
    log("[2/3] malicious Paillier setup")
    prepare_prm(mal, ssid)
    assert mal.prm is not None
    prm_parts = mal.prm.to_bytes_parts()
    prm_ints = [int.from_bytes(part, "big") for part in prm_parts]
    V = sha512_256i(ssid, 0, mal.N, mal.s, mal.t, *prm_ints, mal.rho_aux)
    our_r1 = AuxRound1Message(id=0, V=V)
    our_r2 = AuxRound2Message(
        n=mal.N,
        s=mal.s,
        t=mal.t,
        prm=prm_parts,
        rho=mal.rho_aux,
    )

    client.command(2, "start_phase")
    server_r1 = AuxRound1Message.from_dict(client.command(2, "round1"))
    server_r2 = AuxRound2Message.from_dict(
        client.command(2, "round2", our_r1.to_dict())
    )
    client.command(2, "round3", our_r2.to_dict())

    seed = ssid ^ (mal.rho_aux ^ int(server_r2.rho))
    mod = forge_mod_proof(seed, mal)
    fac = ProofFac.new_proof(
        seed,
        EC,
        mal.N,
        int(server_r2.n),
        int(server_r2.s),
        int(server_r2.t),
        mal.Wbase,
        mal.remaining_prime,
    )
    if not fac.verify(seed, EC, mal.N, server_r2.n, server_r2.s, server_r2.t):
        raise RuntimeError("internal Fac proof failure")
    our_r3 = AuxRound3Message(mod=mod.to_bytes_parts(), fac=fac.to_bytes_parts())
    client.command(2, "round_out", our_r3.to_dict())
    return PublicKey(server_r2.n), int(server_r2.s), int(server_r2.t)


def build_affg_zero_share(
    ssid: int,
    server_pub: PublicKey,
    mal_pub: PublicKey,
    server_s: int,
    server_t: int,
    C: int,
) -> tuple[int, int, ProofAffg]:
    rho = random_unit(int(server_pub.n))
    rhoy = random_unit(int(mal_pub.n))
    enc_one = server_pub.encrypt_with_randomness(1, rho)
    D = server_pub.homo_add(server_pub.homo_mult(Q, C), enc_one)
    F = mal_pub.encrypt_with_randomness(1, rhoy)
    proof = ProofAffg.new_proof(
        ssid,
        EC,
        server_pub,
        mal_pub,
        int(server_pub.n),
        server_s,
        server_t,
        C,
        D,
        F,
        INF,
        Q,
        1,
        rho,
        rhoy,
    )
    return D, F, proof


def attack_round(
    client: Client,
    ssid: int,
    Xi: Point,
    mal: MaliciousPaillier,
    server_pub: PublicKey,
    server_s: int,
    server_t: int,
    prime: int,
    workers: int,
    complete_signing: bool,
    round_number: int,
) -> int:
    log(f"[3/3] leakage round {round_number:02d}/{len(mal.small_primes)} (p={prime})")
    M = mal.N // prime
    Mq = M % Q

    client.command(3, "start_phase")
    server_r1 = PresigningRound1Message.from_dict(client.command(3, "round1"))

    K0, rho_k = mal.pub.encrypt_and_return_randomness(Q)
    hsmall = pow(int(mal.pub.gamma), M, int(mal.pub.n_square))
    Kmal = K0 * hsmall % int(mal.pub.n_square)
    proof_enc = forge_enc(
        ssid,
        mal.pub,
        Kmal,
        rho_k,
        int(server_pub.n),
        server_s,
        server_t,
        prime,
        workers,
    )
    Gct, rho_g = mal.pub.encrypt_and_return_randomness(Q)
    our_r1 = PresigningRound1Message(
        K_ct=Kmal, G_ct=Gct, proofenc=proof_enc.to_bytes_parts()
    )
    server_r2 = PresigningRound2Message.from_dict(
        client.command(3, "round2", our_r1.to_dict())
    )

    Dg, Fg, affg_g = build_affg_zero_share(
        ssid, server_pub, mal.pub, server_s, server_t, server_r1.K_ct
    )
    Dx, Fx, affg_x = build_affg_zero_share(
        ssid, server_pub, mal.pub, server_s, server_t, server_r1.K_ct
    )
    log_g = ProofLogstar.new_proof(
        ssid,
        EC,
        mal.pub,
        Gct,
        INF,
        EC.G,
        rho_g,
        Q,
        int(server_pub.n),
        server_s,
        server_t,
    )
    our_r2 = PresigningRound2Message(
        Gamma=INF,
        D=Dg,
        _D=Dx,
        F=Fg,
        _F=Fx,
        psi_affg_gamma=affg_g.to_bytes_parts(),
        psi_affg_xi=affg_x.to_bytes_parts(),
        psi_logstar_gamma=log_g.to_bytes_parts(),
    )
    server_r3 = PresigningRound3Message.from_dict(
        client.command(3, "round3", our_r2.to_dict())
    )

    dg = mal.priv.decrypt(server_r2.D)
    dx = mal.priv.decrypt(server_r2._D)

    gamma_target = point_sub(
        EC.scalar_mult((int(server_r3.delta) + dg - 1) % Q),
        server_r3.vdelta,
    )
    gamma_base = EC.scalar_mult(Mq)
    zgamma = signed_small_dlog(gamma_base, gamma_target, prime)
    beta_g = (dg - Mq * zgamma) % Q
    peer_delta = (beta_g - 1) % Q

    final_log = forge_logstar(
        ssid,
        mal.pub,
        Kmal,
        rho_k,
        INF,
        server_r2.Gamma,
        int(server_pub.n),
        server_s,
        server_t,
        prime,
        workers,
    )
    our_r3 = PresigningRound3Message(
        delta=peer_delta, vdelta=INF, psi=final_log.to_bytes_parts()
    )
    presig_out = client.command(3, "round_out", our_r3.to_dict())
    R = Point(
        int(presig_out["R"]["x"], 16),
        int(presig_out["R"]["y"], 16),
        EC.curve,
    )

    message = f"z3kapig leakage round {round_number}".encode()
    client.command(4, "start_phase")
    server_sign = SigningMessage.from_dict(
        client.command(4, "sign", {"message": message.hex()})
    )

    xi_target = point_sub(
        point_sub(server_sign.R_chi, Xi),
        EC.scalar_mult((1 - dx) % Q, R),
    )
    xi_base = EC.scalar_mult(Mq, R)
    zxi = signed_small_dlog(xi_base, xi_target, prime)
    residue = zxi % prime
    beta_x = (dx - Mq * zxi) % Q
    log(f"    xi mod {prime} = {residue}")

    if complete_signing:
        r_sig = int(R.x) % Q
        sigma = (r_sig * ((beta_x - 1) % Q)) % Q
        sigma_point = EC.scalar_mult(sigma, R)
        R_chi_peer = EC.scalar_mult((beta_x - 1) % Q, R)
        blind = EC.random_scalar()
        H = second_base_point(EC)
        t_commit = EC.point_add(EC.scalar_mult(sigma), EC.scalar_mult(blind, H))
        proof_st = ProofST.new_proof(
            EC, sigma_point, t_commit, R, H, sigma, blind
        )
        proof_nonce = forge_logstar(
            ssid,
            mal.pub,
            Kmal,
            rho_k,
            INF,
            R,
            int(server_pub.n),
            server_s,
            server_t,
            prime,
            workers,
        )
        peer_sign = SigningMessage(
            sigma=sigma,
            sigma_point=sigma_point,
            R_k=INF,
            R_chi=R_chi_peer,
            t_commit=t_commit,
            proof_st=proof_st.to_bytes_parts(),
            proof_logstar_k=proof_nonce.to_bytes_parts(),
        )
        result = client.command(4, "verify", peer_sign.to_dict())
        if result.get("verify") is not True:
            raise RuntimeError("signing verification unexpectedly failed")

    return residue


def run(args: argparse.Namespace) -> None:
    workers = args.workers or min(8, os.cpu_count() or 1)
    log("[*] generating malicious 2048-bit multiprime Paillier modulus")
    mal = build_malicious_paillier()
    log(
        f"[+] modulus ready: {mal.N.bit_length()} bits, "
        f"CRT product={math.prod(mal.small_primes).bit_length()} bits"
    )

    tube: Tube
    if args.local:
        tube = ProcessTube(args.local_timeout)
    else:
        if args.host is None or args.port is None:
            raise SystemExit("usage: solve.py HOST PORT [--workers N]")
        tube = SocketTube(args.host, args.port)
    client = Client(tube, args.verbose)

    try:
        pow_msg = client.recv_json()
        if pow_msg.get("type") != "pow":
            raise RuntimeError(f"unexpected first message: {pow_msg}")
        challenge = bytes.fromhex(pow_msg["challenge"])
        difficulty = int(pow_msg["difficulty"])
        log(f"[*] solving PoW difficulty {difficulty} with {workers} workers")
        nonce = solve_pow_parallel(challenge, difficulty, workers)
        client.send_json({"nonce": nonce})
        pow_result = client.recv_json()
        if pow_result.get("status") != "ok":
            raise RuntimeError(f"PoW rejected: {pow_result}")
        log("[+] PoW accepted")

        ssid, Xi = perform_keygen(client)
        server_pub, server_s, server_t = perform_aux(client, ssid, mal)

        residues: list[int] = []
        for i, prime in enumerate(mal.small_primes, 1):
            residue = attack_round(
                client,
                ssid,
                Xi,
                mal,
                server_pub,
                server_s,
                server_t,
                prime,
                workers,
                complete_signing=(i < len(mal.small_primes)),
                round_number=i,
            )
            residues.append(residue)

        xi = crt_pairwise(residues, mal.small_primes)
        modulus = math.prod(mal.small_primes)
        if modulus <= Q or not (0 < xi < Q):
            raise RuntimeError(
                f"CRT produced invalid key candidate xi={xi}, modulus_bits={modulus.bit_length()}"
            )
        if EC.scalar_mult(xi) != Xi:
            raise RuntimeError("recovered scalar does not match Xi")
        log(f"[+] recovered xi = {xi}")

        result = client.guess(xi)
        if not result.get("correct"):
            raise RuntimeError(f"key guess rejected: {result}")
        flag = result.get("flag", "")
        print(f"<FLAG>{flag}</FLAG>", flush=True)
    finally:
        tube.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Solver for z3kapig")
    parser.add_argument("host", nargs="?")
    parser.add_argument("port", nargs="?", type=int)
    parser.add_argument("--workers", type=int, default=0)
    parser.add_argument("--local", action="store_true", help="spawn local main.py")
    parser.add_argument("--local-timeout", type=int, default=1800)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    mp.freeze_support()
    run(parse_args())
