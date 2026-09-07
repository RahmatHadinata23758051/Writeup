#!/usr/bin/env python3
"""
CADENCE one-file solver.

Tidak ada `import solve`, jadi aman dinamai solve.py.
Mode lokal:
  python3 solve.py --nonce <SESSION_HEX> --rate <RATE>

Mode auto remote:
  python3 solve.py --remote
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import re
import socket
import ssl
import struct
import sys
import time
import wave
from pathlib import Path

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
GF_POLY = 0x04C11DB7

INIT_DOMAIN = b"cadence/resonance/init/v2"
TARGET_DOMAIN = b"cadence/resonance/target/v2"
SESSION_DOMAIN = b"cadence/encore/session/v2"

# rodata target used by encore.resonates final vptest.
TARGET = [
    0x452821E6,
    0x38D01377,
    0xBE5466CF,
    0x34E90C6C,
    0xC0AC29B7,
    0xC97C50DD,
    0x3F84D5B5,
    0xB5470917,
]

RATES = [8000, 11025, 16000, 22050, 32000, 44100]
FINAL_GF_CONST = 0x27D4EB2F
SAMPLE_COUNT = 51  # Rank 256 with 16-bit samples.

DEFAULT_HOST = "chall-cadence-encore-88913dcf790d0bbc.challs.ctf.thefewchosen.com"
DEFAULT_PORT = 1337

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
HEX32_RE = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{32})(?![0-9a-fA-F])")
RATE_RE = re.compile(r"(?i)(8000|11025|16000|22050|32000|44100)\s*Hz")


def parse_hex_bytes(text: str, want_len: int, label: str) -> bytes:
    cleaned = "".join(re.findall(r"[0-9a-fA-F]", text))
    if len(cleaned) != want_len * 2:
        raise SystemExit(f"{label} harus {want_len} byte / {want_len * 2} hex chars")
    return bytes.fromhex(cleaned)


def gf_mul(a: int, b: int) -> int:
    """GF(2^32) multiply from encore.gfmul, polynomial 0x04C11DB7."""
    a &= MASK32
    b &= MASK32
    out = 0
    for _ in range(32):
        if b & 1:
            out ^= a
        carry = a & 0x80000000
        a = ((a << 1) & MASK32) ^ (GF_POLY if carry else 0)
        b >>= 1
    return out & MASK32


def gf_pow(a: int, e: int) -> int:
    out = 1
    while e:
        if e & 1:
            out = gf_mul(out, a)
        a = gf_mul(a, a)
        e >>= 1
    return out


INV_FINAL_GF_CONST = gf_pow(FINAL_GF_CONST, (1 << 32) - 2)


def rol32(x: int, n: int) -> int:
    x &= MASK32
    n &= 31
    if n == 0:
        return x
    return ((x << n) | (x >> (32 - n))) & MASK32


def prf_words(domain: bytes, nonce: bytes, rate: int = 0, include_rate: bool = False) -> list[int]:
    msg = domain + nonce
    if include_rate:
        msg += struct.pack("<I", rate)
    digest = hashlib.sha256(msg).digest()
    # Binary stores SHA digest bytes and then reads dwords little-endian.
    return list(struct.unpack("<8I", digest))


def session_nonce(seed: bytes) -> bytes:
    return hashlib.sha256(SESSION_DOMAIN + seed).digest()[:16]


def required_rate(nonce: bytes) -> int:
    return RATES[nonce[0] % len(RATES)]


def splitmix_next(seed: int) -> tuple[int, int]:
    seed = (seed + 0x9E3779B97F4A7C15) & MASK64
    z = seed
    z = (z ^ (z >> 30)) & MASK64
    z = (z * 0xBF58476D1CE4E5B9) & MASK64
    z = (z ^ (z >> 27)) & MASK64
    z = (z * 0x94D049BB133111EB) & MASK64
    z = (z ^ (z >> 31)) & MASK64
    return seed, z


def simulate(samples: list[int], nonce: bytes, rate: int) -> list[int]:
    nonce_words = list(struct.unpack("<4I", nonce))
    state = prf_words(INIT_DOMAIN, nonce, rate, include_rate=True)
    seed = 0xC0DACE5551A7E001

    for i, sample in enumerate(samples):
        seed, d = splitmix_next(seed)
        sample &= 0xFFFF

        dst = d & 7
        src = (d >> 3) & 7
        if src == dst:
            src = (src + 1) & 7

        sample_rot = ((d >> 9) % 31) + 1
        key_rot = ((i + src) % 31) + 1
        key = rol32(nonce_words[(i + d) & 3], key_rot)

        old_dst = state[dst]
        op = (d >> 6) & 3
        if op == 0:
            new = old_dst ^ key ^ rol32(sample, sample_rot) ^ gf_mul(state[src], 0x9E3779B1)
            state[dst] = new & MASK32
        elif op == 1:
            new = state[src] ^ key ^ rol32(old_dst, sample_rot) ^ gf_mul(sample, 0x85EBCA77)
            state[dst] = new & MASK32
        elif op == 2:
            new = old_dst ^ key ^ rol32(state[src], sample_rot) ^ gf_mul(sample, 0xC2B2AE3D)
            state[dst] = new & MASK32
        else:
            # Annoying swap case in jump-table slot 3:
            #   state[dst] = sample ^ state[src] ^ key
            #   state[src] = old_dst
            new = sample ^ state[src] ^ key
            state[dst] = new & MASK32
            state[src] = old_dst & MASK32

    return state


def wanted_final_state(nonce: bytes, rate: int) -> list[int]:
    nonce_words = list(struct.unpack("<4I", nonce))
    target_prf = prf_words(TARGET_DOMAIN, nonce, rate, include_rate=False)

    # Final vector before xor with target_prf and TARGET:
    # [g5,g2,g7,g0,n0,n1,n2,n3] XOR [n0,n1,n2,n3,g3,g6,g1,g4]
    wanted_g = [0] * 8
    wanted_g[5] = TARGET[0] ^ target_prf[0] ^ nonce_words[0]
    wanted_g[2] = TARGET[1] ^ target_prf[1] ^ nonce_words[1]
    wanted_g[7] = TARGET[2] ^ target_prf[2] ^ nonce_words[2]
    wanted_g[0] = TARGET[3] ^ target_prf[3] ^ nonce_words[3]
    wanted_g[3] = TARGET[4] ^ target_prf[4] ^ nonce_words[0]
    wanted_g[6] = TARGET[5] ^ target_prf[5] ^ nonce_words[1]
    wanted_g[1] = TARGET[6] ^ target_prf[6] ^ nonce_words[2]
    wanted_g[4] = TARGET[7] ^ target_prf[7] ^ nonce_words[3]

    return [gf_mul(x, INV_FINAL_GF_CONST) for x in wanted_g]


def final_check(state: list[int], nonce: bytes, rate: int) -> bool:
    nonce_words = list(struct.unpack("<4I", nonce))
    target_prf = prf_words(TARGET_DOMAIN, nonce, rate, include_rate=False)
    g = [gf_mul(x, FINAL_GF_CONST) for x in state]
    vec0 = [g[5], g[2], g[7], g[0], nonce_words[0], nonce_words[1], nonce_words[2], nonce_words[3]]
    vec1 = [nonce_words[0], nonce_words[1], nonce_words[2], nonce_words[3], g[3], g[6], g[1], g[4]]
    return [vec0[i] ^ vec1[i] ^ target_prf[i] for i in range(8)] == TARGET


def pack_state(state: list[int]) -> int:
    out = 0
    for i, word in enumerate(state):
        out |= (word & MASK32) << (32 * i)
    return out


def solve_samples(nonce: bytes, rate: int, count: int = SAMPLE_COUNT) -> list[int]:
    zero_samples = [0] * count
    zero_state = simulate(zero_samples, nonce, rate)
    wanted_state = wanted_final_state(nonce, rate)
    rhs = pack_state(zero_state) ^ pack_state(wanted_state)

    basis = [0] * 256
    basis_combo = [0] * 256
    rank = 0

    # Linear map: every input bit among count*16 sample bits -> 256-bit state delta.
    for bit in range(count * 16):
        samples = [0] * count
        samples[bit // 16] = 1 << (bit % 16)
        column = pack_state(simulate(samples, nonce, rate)) ^ pack_state(zero_state)

        v = column
        combo = 1 << bit
        while v:
            pivot = v.bit_length() - 1
            if basis[pivot]:
                v ^= basis[pivot]
                combo ^= basis_combo[pivot]
            else:
                basis[pivot] = v
                basis_combo[pivot] = combo
                rank += 1
                break

    if rank != 256:
        raise RuntimeError(f"basis rank {rank}, expected 256")

    solution = 0
    v = rhs
    while v:
        pivot = v.bit_length() - 1
        if not basis[pivot]:
            raise RuntimeError("target state is outside generated span")
        v ^= basis[pivot]
        solution ^= basis_combo[pivot]

    samples = [0] * count
    for bit in range(count * 16):
        if (solution >> bit) & 1:
            samples[bit // 16] |= 1 << (bit % 16)

    state = simulate(samples, nonce, rate)
    if state != wanted_state or not final_check(state, nonce, rate):
        raise RuntimeError("internal verification failed")
    return samples


def write_wav(path: Path, samples: list[int], rate: int) -> None:
    frames = b"".join(struct.pack("<H", s & 0xFFFF) for s in samples)
    with wave.open(str(path), "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(rate)
        wav.writeframes(frames)


def build_payload(kind: str, raw: bytes, rate_arg: int | None, wav_path: Path, payload_path: Path) -> tuple[str, bytes, int]:
    if kind == "seed":
        nonce = session_nonce(raw)
    elif kind == "nonce":
        nonce = raw
    else:
        raise ValueError(f"bad kind: {kind}")
    rate = rate_arg if rate_arg is not None else required_rate(nonce)
    samples = solve_samples(nonce, rate)
    write_wav(wav_path, samples, rate)
    payload = base64.b64encode(wav_path.read_bytes()).decode()
    payload_path.write_text(payload + "\n")
    return payload, nonce, rate


def clean_terminal(s: str) -> str:
    return ANSI_RE.sub("", s).replace("\r", "\n")


def parse_remote_params(text: str) -> tuple[bytes | None, int | None]:
    t = clean_terminal(text)
    m = re.search(r"(?is)(?:SESSION|nonce)[^0-9a-fA-F]{0,80}([0-9a-fA-F]{32})", t)
    if not m:
        vals = HEX32_RE.findall(t)
        m_val = vals[0] if len(vals) == 1 else None
    else:
        m_val = m.group(1)
    rm = RATE_RE.search(t)
    return (bytes.fromhex(m_val) if m_val else None, int(rm.group(1)) if rm else None)


def recv_some(sock: ssl.SSLSocket, total_seconds: float = 10.0, idle_seconds: float = 0.5) -> str:
    sock.setblocking(False)
    out = bytearray()
    end = time.time() + total_seconds
    last = time.time()
    while time.time() < end:
        try:
            chunk = sock.recv(8192)
            if not chunk:
                break
            out += chunk
            last = time.time()
        except (BlockingIOError, ssl.SSLWantReadError):
            if out and time.time() - last >= idle_seconds:
                break
            time.sleep(0.05)
    return out.decode("utf-8", "replace")


def remote_mode(args: argparse.Namespace) -> None:
    transcript = ""
    ctx = ssl.create_default_context()
    with socket.create_connection((args.host, args.port), timeout=15) as tcp:
        with ctx.wrap_socket(tcp, server_hostname=args.host) as s:
            nonce = None
            rate = args.rate
            for _ in range(4):
                chunk = recv_some(s, total_seconds=args.read_timeout, idle_seconds=0.6)
                if chunk:
                    print(chunk, end="")
                    transcript += chunk
                p_nonce, p_rate = parse_remote_params(transcript)
                nonce = nonce or p_nonce
                rate = rate or p_rate
                if nonce is not None:
                    break
            if nonce is None:
                raise SystemExit("[-] SESSION/nonce 32 hex tidak ketemu dari remote output")

            payload, nonce, rate = build_payload(
                "nonce",
                nonce,
                rate,
                Path(args.wav),
                Path(args.payload),
            )
            print(f"\n[+] SESSION/nonce : {nonce.hex()}")
            print(f"[+] rate          : {rate}")
            print(f"[+] wav           : {args.wav}")
            print(f"[+] payload       : {args.payload} ({len(payload)} chars)")
            if args.no_submit:
                print("[+] no-submit aktif, paste isi payload file manual.")
                return
            s.sendall(payload.encode() + b"\n")
            print("[+] payload sent")
            tail = recv_some(s, total_seconds=args.after_timeout, idle_seconds=1.0)
            if tail:
                print(tail, end="")


def main() -> None:
    ap = argparse.ArgumentParser(description="CADENCE one-file solver: generate/submit resonant WAV")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--nonce", help="SESSION/nonce dari remote, 16 byte / 32 hex")
    src.add_argument("--seed", help="seed 16 byte / 32 hex; nonce=SHA256(session_domain||seed)[:16]")
    ap.add_argument("--rate", type=int, help="sample rate dari remote, contoh 8000/16000")
    ap.add_argument("--wav", default="resonant.wav", help="output WAV")
    ap.add_argument("--payload", default="payload.txt", help="output base64 payload")

    ap.add_argument("--remote", action="store_true", help="connect SSL remote, parse SESSION/rate, generate, submit")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--read-timeout", type=float, default=8.0)
    ap.add_argument("--after-timeout", type=float, default=8.0)
    ap.add_argument("--no-submit", action="store_true")
    args = ap.parse_args()

    if args.remote:
        remote_mode(args)
        return

    if args.seed:
        kind, raw = "seed", parse_hex_bytes(args.seed, 16, "seed")
    elif args.nonce:
        kind, raw = "nonce", parse_hex_bytes(args.nonce, 16, "nonce")
    else:
        ap.error("pilih --nonce/--seed, atau pakai --remote")

    payload, nonce, rate = build_payload(kind, raw, args.rate, Path(args.wav), Path(args.payload))
    print(f"nonce      : {nonce.hex()}")
    print(f"rate       : {rate}")
    print(f"samples    : {SAMPLE_COUNT}")
    print(f"wav        : {args.wav}")
    print(f"payload    : {args.payload}")
    print(f"base64 WAV : {payload}")


if __name__ == "__main__":
    main()
