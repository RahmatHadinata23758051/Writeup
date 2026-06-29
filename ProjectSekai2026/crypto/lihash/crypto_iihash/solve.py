#!/usr/bin/env python3
from __future__ import annotations

import argparse
import functools
import random
import re
import socket
import subprocess
import threading
import time
from typing import Iterable

import numpy as np
import xxhash

try:
    from fpylll import BKZ, LLL, IntegerMatrix
except ImportError as exc:
    raise SystemExit(
        "Missing fpylll. Install dependencies with: "
        "pip install xxhash numpy fpylll cysignals"
    ) from exc

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1
P32_1 = 0x9E3779B1
P32_2 = 0x85EBCA77
P32_3 = 0xC2B2AE3D
P64_1 = 0x9E3779B185EBCA87
P64_2 = 0xC2B2AE3D27D4EB4F
P64_3 = 0x165667B19E3779F9
P64_4 = 0x85EBCA77C2B2AE63
P64_5 = 0x27D4EB2F165667C5
AVALANCHE_MUL = 0x165667919E3779F9
TARGET = b"Give me the flag"

DEFAULT_SECRET = bytes([
    0xB8,0xFE,0x6C,0x39,0x23,0xA4,0x4B,0xBE,0x7C,0x01,0x81,0x2C,0xF7,0x21,0xAD,0x1C,
    0xDE,0xD4,0x6D,0xE9,0x83,0x90,0x97,0xDB,0x72,0x40,0xA4,0xA4,0xB7,0xB3,0x67,0x1F,
    0xCB,0x79,0xE6,0x4E,0xCC,0xC0,0xE5,0x78,0x82,0x5A,0xD0,0x7D,0xCC,0xFF,0x72,0x21,
    0xB8,0x08,0x46,0x74,0xF7,0x43,0x24,0x8E,0xE0,0x35,0x90,0xE6,0x81,0x3A,0x26,0x4C,
    0x3C,0x28,0x52,0xBB,0x91,0xC3,0x00,0xCB,0x88,0xD0,0x65,0x8B,0x1B,0x53,0x2E,0xA3,
    0x71,0x64,0x48,0x97,0xA2,0x0D,0xF9,0x4E,0x38,0x19,0xEF,0x46,0xA9,0xDE,0xAC,0xD8,
    0xA8,0xFA,0x76,0x3F,0xE3,0x9C,0x34,0x3F,0xF9,0xDC,0xBB,0xC7,0xC7,0x0B,0x4F,0x1D,
    0x8A,0x51,0xE0,0x4B,0xCD,0xB4,0x59,0x31,0xC8,0x9F,0x7E,0xC9,0xD9,0x78,0x73,0x64,
    0xEA,0xC5,0xAC,0x83,0x34,0xD3,0xEB,0xC3,0xC5,0x81,0xA0,0xFF,0xFA,0x13,0x63,0xEB,
    0x17,0x0D,0xDD,0x51,0xB7,0xF0,0xDA,0x49,0xD3,0x16,0x55,0x26,0x29,0xD4,0x68,0x9E,
    0x2B,0x16,0xBE,0x58,0x7D,0x47,0xA1,0xFC,0x8F,0xF8,0xB8,0xD1,0x7A,0xD0,0x31,0xCE,
    0x45,0xCB,0x3A,0x8F,0x95,0x16,0x04,0x28,0xAF,0xD7,0xFB,0xCA,0xBB,0x4B,0x40,0x7E,
])

INIT_ACC = [P32_3, P64_1, P64_2, P64_3, P64_4, P32_2, P64_5, P32_1]
C_WORDS = [int.from_bytes(DEFAULT_SECRET[8*i:8*i+8], "little") for i in range(24)]


def xxh_hex(data: bytes, seed: int) -> str:
    return xxhash.xxh3_128(data, seed=seed).hexdigest()


def xxh_digest(data: bytes, seed: int) -> bytes:
    return xxhash.xxh3_128(data, seed=seed).digest()


def u64(data: bytes, off: int = 0) -> int:
    return int.from_bytes(data[off:off+8], "little")


def custom_secret(seed: int) -> bytes:
    out = bytearray(192)
    for i in range(12):
        lo = (u64(DEFAULT_SECRET, 16*i) + seed) & MASK64
        hi = (u64(DEFAULT_SECRET, 16*i+8) - seed) & MASK64
        out[16*i:16*i+8] = lo.to_bytes(8, "little")
        out[16*i+8:16*i+16] = hi.to_bytes(8, "little")
    return bytes(out)


def fold128(a: int, b: int) -> int:
    p = a * b
    return ((p & MASK64) ^ (p >> 64)) & MASK64


def avalanche(x: int) -> int:
    x ^= x >> 37
    x = (x * AVALANCHE_MUL) & MASK64
    x ^= x >> 32
    return x & MASK64


def inverse_avalanche(y: int) -> int:
    # Both shifts exceed half the word size, so one reverse-xorshift step is enough.
    x = y ^ (y >> 32)
    x = (x * pow(AVALANCHE_MUL, -1, 1 << 64)) & MASK64
    x ^= x >> 37
    return x & MASK64


def accum_stripe(acc: list[int], data: bytes, off: int, secret: bytes, soff: int) -> None:
    for lane in range(8):
        d = u64(data, off + 8*lane)
        k = u64(secret, soff + 8*lane)
        q = d ^ k
        acc[lane ^ 1] = (acc[lane ^ 1] + d) & MASK64
        acc[lane] = (acc[lane] + (q & MASK32) * (q >> 32)) & MASK64


def model_hash_320(data: bytes, seed: int) -> tuple[int, int, list[int]]:
    if len(data) != 320:
        raise ValueError("model_hash_320 expects exactly 320 bytes")
    secret = custom_secret(seed)
    acc = INIT_ACC.copy()
    for stripe in range(4):
        accum_stripe(acc, data, 64*stripe, secret, 8*stripe)
    accum_stripe(acc, data, 256, secret, 121)

    lo = (320 * P64_1) & MASK64
    hi = (~(320 * P64_2)) & MASK64
    for i in range(4):
        lo = (lo + fold128(
            acc[2*i] ^ u64(secret, 11 + 16*i),
            acc[2*i+1] ^ u64(secret, 19 + 16*i),
        )) & MASK64
        hi = (hi + fold128(
            acc[2*i] ^ u64(secret, 117 + 16*i),
            acc[2*i+1] ^ u64(secret, 125 + 16*i),
        )) & MASK64
    return avalanche(lo), avalanche(hi), acc


# ---------------------------------------------------------------------------
# Seed-recovery arithmetic
# ---------------------------------------------------------------------------


def count_preimages_sumxor(Q: int, R: int) -> int:
    states = {0: 1}
    for i in range(32):
        q = (Q >> i) & 1
        r = (R >> i) & 1
        nxt: dict[int, int] = {}
        for carry, count in states.items():
            for xb in (0, 1):
                yb = xb ^ r
                total = xb + yb + carry
                if (total & 1) == q:
                    nxt[total >> 1] = nxt.get(total >> 1, 0) + count
        states = nxt
        if not states:
            return 0
    return sum(states.values())


@functools.lru_cache(maxsize=128)
def possible_r_cached(Q: int) -> np.ndarray:
    Q &= MASK32
    states = [np.array([0], dtype=np.uint32), np.array([], dtype=np.uint32)]
    for i in range(32):
        q = (Q >> i) & 1
        bit = np.uint32(1 << i)
        outs: list[list[np.ndarray]] = [[], []]
        for carry, arr in enumerate(states):
            if arr.size == 0:
                continue
            if q == carry:
                outs[0].append(arr)
                outs[1].append(arr)
            else:
                outs[carry].append(arr | bit)
        states = []
        for parts in outs:
            if not parts:
                states.append(np.array([], dtype=np.uint32))
            elif len(parts) == 1:
                states.append(parts[0].copy())
            else:
                states.append(np.unique(np.concatenate(parts)))
    return np.unique(np.concatenate([x for x in states if x.size]))


def invert_sum_xor(Q: int, R: int) -> np.ndarray:
    states: dict[int, np.ndarray] = {0: np.array([0], dtype=np.uint32)}
    for i in range(32):
        q = (Q >> i) & 1
        r = (R >> i) & 1
        outs: dict[int, list[np.ndarray]] = {0: [], 1: []}
        for carry, arr in states.items():
            for xb in (0, 1):
                yb = xb ^ r
                total = xb + yb + carry
                if (total & 1) == q:
                    outs[total >> 1].append(arr | np.uint32(xb << i))
        states = {
            c: parts[0] if len(parts) == 1 else np.concatenate(parts)
            for c, parts in outs.items() if parts
        }
        if not states:
            return np.array([], dtype=np.uint32)
    return np.concatenate(list(states.values()))


def low_word(seed_low: int, index: int) -> int:
    c = C_WORDS[index] & MASK32
    return (c + seed_low) & MASK32 if index % 2 == 0 else (c - seed_low) & MASK32


def high_word(seed_low: int, seed_high: int, index: int) -> int:
    c_lo = C_WORDS[index] & MASK32
    c_hi = C_WORDS[index] >> 32
    if index % 2 == 0:
        carry = int(c_lo + seed_low > MASK32)
        return (c_hi + seed_high + carry) & MASK32
    borrow = int(c_lo < seed_low)
    return (c_hi - seed_high - borrow) & MASK32


def relation_low_vec(seeds: np.ndarray, i: int, j: int) -> np.ndarray:
    s = seeds.astype(np.uint64)

    def part(k: int) -> np.ndarray:
        c = np.uint64(C_WORDS[k] & MASK32)
        return ((c + s) if k % 2 == 0 else (c - s)) & np.uint64(MASK32)

    return (part(i) ^ part(j)).astype(np.uint32)


def relation_high_vec(seed_lows: np.ndarray, seed_highs: np.ndarray, i: int, j: int) -> np.ndarray:
    sl = seed_lows.astype(np.uint64)
    sh = seed_highs.astype(np.uint64)

    def part(k: int) -> np.ndarray:
        c_lo = C_WORDS[k] & MASK32
        c_hi = C_WORDS[k] >> 32
        if k % 2 == 0:
            carry = (sl > np.uint64(MASK32 - c_lo)).astype(np.uint64)
            return (np.uint64(c_hi) + sh + carry) & np.uint64(MASK32)
        borrow = (sl > np.uint64(c_lo)).astype(np.uint64)
        return (np.uint64(c_hi) - sh - borrow) & np.uint64(MASK32)

    return (part(i) ^ part(j)).astype(np.uint32)


def pair_placement(i: int, j: int) -> tuple[int, int, int, int]:
    i, j = sorted((int(i), int(j)))
    lo = max(0, j - 14)
    hi = min(7, i)
    if lo > hi:
        raise ValueError("secret words cannot share a regular lane")
    lane = hi
    stripe_i = i - lane
    stripe_j = j - lane
    length = max(320, 64 * (max(stripe_i, stripe_j) + 2))
    return lane, stripe_i, stripe_j, length


def initial_low_distribution(i: int, j: int) -> tuple[np.ndarray, np.ndarray]:
    if not ((i ^ j) & 1):
        raise ValueError("initial relation requires opposite parity")
    plus = i if i % 2 == 0 else j
    minus = j if i % 2 == 0 else i
    Q = ((C_WORDS[plus] & MASK32) + (C_WORDS[minus] & MASK32)) & MASK32
    vals = possible_r_cached(Q)
    weights = np.array([count_preimages_sumxor(Q, int(r)) for r in vals], dtype=np.uint64)
    return vals, weights


def low_candidates_from_relation(i: int, j: int, R: int) -> np.ndarray:
    plus = i if i % 2 == 0 else j
    minus = j if i % 2 == 0 else i
    Q = ((C_WORDS[plus] & MASK32) + (C_WORDS[minus] & MASK32)) & MASK32
    x_plus = invert_sum_xor(Q, R)
    seeds = ((x_plus.astype(np.uint64) - np.uint64(C_WORDS[plus] & MASK32)) & np.uint64(MASK32)).astype(np.uint32)
    relation = relation_low_vec(seeds, i, j)
    return np.unique(seeds[relation == np.uint32(R)])


def qhigh_pair(seed_low: int, i: int, j: int) -> int:
    plus = i if i % 2 == 0 else j
    minus = j if i % 2 == 0 else i
    cp = C_WORDS[plus] & MASK32
    cm = C_WORDS[minus] & MASK32
    carry = int(cp + seed_low > MASK32)
    borrow = int(cm < seed_low)
    return ((C_WORDS[plus] >> 32) + (C_WORDS[minus] >> 32) + carry - borrow) & MASK32


def high_candidates_from_relation(seed_low: int, i: int, j: int, R: int) -> np.ndarray:
    plus = i if i % 2 == 0 else j
    Q = qhigh_pair(seed_low, i, j)
    b_plus = invert_sum_xor(Q, R)
    if b_plus.size == 0:
        return b_plus
    cp = C_WORDS[plus] & MASK32
    carry = int(cp + seed_low > MASK32)
    seed_highs = ((b_plus.astype(np.uint64) - np.uint64((C_WORDS[plus] >> 32) + carry)) & np.uint64(MASK32)).astype(np.uint32)
    lows = np.full(seed_highs.size, np.uint32(seed_low), dtype=np.uint32)
    relation = relation_high_vec(lows, seed_highs, i, j)
    return np.unique(seed_highs[relation == np.uint32(R)])


def initial_high_distribution(low_candidates: np.ndarray, i: int, j: int) -> tuple[np.ndarray, np.ndarray]:
    qs = [qhigh_pair(int(s), i, j) for s in low_candidates]
    arrays = [possible_r_cached(q) for q in qs]
    vals = np.unique(np.concatenate(arrays))
    weights = np.array([
        sum(count_preimages_sumxor(q, int(r)) for q in qs)
        for r in vals
    ], dtype=np.uint64)
    return vals, weights


# Small DFA for counting valid XOR outputs of x+y=Q without materializing them.
def _carry_transition(state: int, q: int, r: int) -> int:
    if state == 0:
        return 0
    if r == 0:
        return 3 if state & (1 << q) else 0
    carry = 1 - q
    return (1 << carry) if state & (1 << carry) else 0


def count_relation_union(qs: Iterable[int]) -> int:
    uniq = tuple(dict.fromkeys(int(q) & MASK32 for q in qs))
    dp: dict[tuple[int, ...], int] = {(1,) * len(uniq): 1}
    for bit in range(32):
        nxt: dict[tuple[int, ...], int] = {}
        for states, count in dp.items():
            for r in (0, 1):
                ns = tuple(_carry_transition(states[k], (uniq[k] >> bit) & 1, r) for k in range(len(uniq)))
                if any(ns):
                    nxt[ns] = nxt.get(ns, 0) + count
        dp = nxt
    return sum(dp.values())


# ---------------------------------------------------------------------------
# Chosen-input collision oracle
# ---------------------------------------------------------------------------

LOW_INIT = (2, 7)
LOW_FILTERS = [
    (0,2),(6,8),(0,1),(6,9),(1,3),(3,5),(5,7),(7,11),(11,13),
    (8,11),(1,4),(8,9),(2,5),(3,8),(9,11),(10,11),(4,6),(7,8),
]
ALL_PAIRS: list[tuple[int, int, int]] = []
OPPOSITE_PAIRS: list[tuple[int, int, int]] = []
for _i in range(15):
    for _j in range(_i + 1, 15):
        try:
            _n = pair_placement(_i, _j)[3]
        except ValueError:
            continue
        ALL_PAIRS.append((_i, _j, _n))
        if (_i ^ _j) & 1:
            OPPOSITE_PAIRS.append((_i, _j, _n))


def relation_messages(R: int, pair: tuple[int, int], bit: int, kind: str) -> tuple[bytes, bytes]:
    i, j = pair
    lane, stripe_i, stripe_j, length = pair_placement(i, j)
    off_i = 64 * stripe_i + 8 * lane
    off_j = 64 * stripe_j + 8 * lane
    a = bytearray(length)
    b = bytearray(length)

    if kind == "low":
        a[off_j:off_j+8] = (((1 << bit) << 32) | R).to_bytes(8, "little")
        b[off_i:off_i+8] = ((1 << bit) << 32).to_bytes(8, "little")
        b[off_j:off_j+8] = R.to_bytes(8, "little")
    elif kind == "high":
        a[off_j:off_j+8] = ((R << 32) | (1 << bit)).to_bytes(8, "little")
        b[off_i:off_i+8] = (1 << bit).to_bytes(8, "little")
        b[off_j:off_j+8] = (R << 32).to_bytes(8, "little")
    else:
        raise ValueError(kind)
    return bytes(a), bytes(b)


def ordered_candidates(vals: np.ndarray, weights: np.ndarray) -> np.ndarray:
    return np.asarray(vals, dtype=np.uint32)[
        np.argsort(-np.asarray(weights, dtype=np.int64), kind="stable")
    ]


def final_carries(Q: int, R: int) -> set[int]:
    states = {0}
    for i in range(32):
        q = (Q >> i) & 1
        r = (R >> i) & 1
        nxt: set[int] = set()
        for carry in states:
            for xb in (0, 1):
                yb = xb ^ r
                total = xb + yb + carry
                if (total & 1) == q:
                    nxt.add(total >> 1)
        states = nxt
        if not states:
            break
    return states


def guaranteed_high_equal_bits(pair: tuple[int, int], R: int) -> list[int]:
    i, j = pair
    plus = i if i % 2 == 0 else j
    minus = j if i % 2 == 0 else i
    cp = C_WORDS[plus] & MASK32
    cm = C_WORDS[minus] & MASK32
    low_sum = cp + cm
    Q_low = low_sum & MASK32
    qcarry = low_sum >> 32
    high_base = ((C_WORDS[plus] >> 32) + (C_WORDS[minus] >> 32)) & MASK32

    bits: list[int] = []
    for carry_out in final_carries(Q_low, R):
        Q_high = (high_base + qcarry - carry_out) & MASK32
        for bit in range(32):
            if ((Q_high >> bit) & 1) == 0:
                bits.append(bit)
                break
    return sorted(set(bits))


def find_unknown_low_relation(oracle, vals: np.ndarray, weights: np.ndarray, pair: tuple[int, int]) -> int:
    vals = ordered_candidates(vals, weights)
    batch_size = 64
    for start in range(0, len(vals), batch_size):
        chunk = vals[start:start+batch_size]
        payloads: list[bytes] = []
        metadata: list[tuple[int, int]] = []
        for r_np in chunk:
            r = int(r_np)
            bits = guaranteed_high_equal_bits(pair, r) if ((pair[0] ^ pair[1]) & 1) else range(6)
            for bit in bits:
                payloads.extend(relation_messages(r, pair, bit, "low"))
                metadata.append((r, len(payloads) - 2))
        hashes = oracle.hash_many(payloads)
        for r, pos in metadata:
            if hashes[pos] == hashes[pos + 1]:
                return r
    raise RuntimeError("low relation was not found")


def find_known_high_relation(
    oracle,
    vals: np.ndarray,
    weights: np.ndarray,
    pair: tuple[int, int],
    bit: int,
) -> int:
    vals = ordered_candidates(vals, weights)
    batch_size = 64
    for start in range(0, len(vals), batch_size):
        chunk = vals[start:start+batch_size]
        payloads: list[bytes] = []
        for r_np in chunk:
            payloads.extend(relation_messages(int(r_np), pair, bit, "high"))
        hashes = oracle.hash_many(payloads)
        for idx, r_np in enumerate(chunk):
            if hashes[2*idx] == hashes[2*idx + 1]:
                return int(r_np)
    raise RuntimeError("high relation was not found")


def common_zero_bit(low_values: np.ndarray, pair: tuple[int, int]) -> int | None:
    rel = relation_low_vec(np.asarray(low_values, dtype=np.uint32), *pair)
    for bit in range(32):
        if np.all(((rel >> np.uint32(bit)) & np.uint32(1)) == 0):
            return bit
    return None


def expected_guesswork(weights: np.ndarray) -> float:
    w = np.asarray(weights, dtype=np.float64)
    order = np.argsort(-w, kind="stable")
    return float(np.dot(np.arange(1, len(w) + 1), w[order]) / w.sum())


def recover_low_half(oracle, verbose: bool = True) -> np.ndarray:
    vals, weights = initial_low_distribution(*LOW_INIT)
    relation = find_unknown_low_relation(oracle, vals, weights, LOW_INIT)
    candidates = low_candidates_from_relation(*LOW_INIT, relation)
    if verbose:
        print(f"[+] low relation {LOW_INIT}: {relation:#010x}; candidates={len(candidates)}; queries={oracle.queries}", flush=True)

    # A low-relation collision is deterministic only for opposite-parity
    # secret words (+seed versus -seed).  Same-parity pairs require the
    # unknown high words to share a tested bit; the old range(6) heuristic
    # can therefore miss the true relation for unlucky seeds.
    safe_low_filters = [pair for pair in LOW_FILTERS if (pair[0] ^ pair[1]) & 1]
    for pair in safe_low_filters:
        if len(candidates) <= 2:
            break
        rv = relation_low_vec(candidates, *pair)
        vals, counts = np.unique(rv, return_counts=True)
        if len(vals) <= 1:
            continue
        relation = find_unknown_low_relation(oracle, vals, counts, pair)
        candidates = candidates[rv == np.uint32(relation)]
        if verbose:
            print(f"[+] low filter {pair}: remain={len(candidates)}; queries={oracle.queries}", flush=True)
    return candidates


def high_pair_pool(low_candidates: np.ndarray, verbose: bool = True, limit: int = 6):
    coarse = []
    for i, j, length in OPPOSITE_PAIRS:
        if common_zero_bit(low_candidates, (i, j)) is None:
            continue
        qs = sorted(set(qhigh_pair(int(x), i, j) for x in low_candidates))
        coarse.append((count_relation_union(qs), length, (i, j)))

    pool = []
    for _, length, pair in sorted(coarse)[:limit]:
        vals, weights = initial_high_distribution(low_candidates, *pair)
        expected = expected_guesswork(weights)
        pool.append({
            "pair": pair,
            "length": length,
            "vals": vals,
            "weights": weights,
            "expected": expected,
        })
        if verbose:
            print(
                f"[*] high pool {pair}: relations={len(vals)}, "
                f"expected-tests={expected:.1f}, max-preimages={int(weights.max())}",
                flush=True,
            )
    pool.sort(key=lambda x: (x["expected"], x["length"]))
    return pool


def choose_filter_pair(seed_lows: np.ndarray, seed_highs: np.ndarray):
    count = len(seed_highs)
    unique_lows = np.unique(seed_lows)
    best = None
    for i, j, length in ALL_PAIRS:
        bit = common_zero_bit(unique_lows, (i, j))
        if bit is None:
            continue
        rv = relation_high_vec(seed_lows, seed_highs, i, j)
        vals, weights = np.unique(rv, return_counts=True)
        if len(vals) <= 1:
            continue
        probabilities = weights.astype(np.float64) / count
        entropy = float(-np.sum(probabilities * np.log2(probabilities)))
        if entropy <= 0:
            continue
        expected = expected_guesswork(weights)
        expected_remaining = float(np.dot(weights.astype(np.float64), weights.astype(np.float64)) / count)
        key = (expected * length / entropy, expected_remaining, expected * length)
        if best is None or key < best[0]:
            best = (key, (i, j), bit, rv, vals, weights)
    if best is None:
        raise RuntimeError("no useful high-half filter")
    return best


def recover_seed(oracle, verbose: bool = True) -> int:
    low_candidates = recover_low_half(oracle, verbose)
    pool = high_pair_pool(low_candidates, verbose)

    relations: list[tuple[tuple[int, int], int, int]] = []
    for entry in pool:
        pair = entry["pair"]
        bit = common_zero_bit(low_candidates, pair)
        assert bit is not None
        relation = find_known_high_relation(
            oracle, entry["vals"], entry["weights"], pair, bit
        )
        pos = np.where(entry["vals"] == np.uint32(relation))[0]
        preimages = int(entry["weights"][pos[0]]) if len(pos) else (1 << 32)
        relations.append((pair, relation, preimages))
        if verbose:
            print(
                f"[+] high relation {pair}: {relation:#010x}; "
                f"preimages={preimages}; queries={oracle.queries}",
                flush=True,
            )
        if len(relations) >= 2 and min(x[2] for x in relations) <= 1_000_000:
            break
        if len(relations) >= 3:
            break

    base = min(relations, key=lambda x: x[2])
    other_relations = [item for item in relations if item is not base]
    low_parts: list[np.ndarray] = []
    high_parts: list[np.ndarray] = []

    for low_np in low_candidates:
        low = int(low_np)
        highs = high_candidates_from_relation(low, *base[0], base[1])
        if len(highs) == 0:
            continue
        lows = np.full(len(highs), np.uint32(low), dtype=np.uint32)
        for pair, relation, _ in other_relations:
            keep = relation_high_vec(lows, highs, *pair) == np.uint32(relation)
            lows = lows[keep]
            highs = highs[keep]
            if len(highs) == 0:
                break
        if len(highs):
            low_parts.append(lows)
            high_parts.append(highs)

    if not high_parts:
        raise RuntimeError("all high-half candidates were eliminated")
    seed_lows = np.concatenate(low_parts)
    seed_highs = np.concatenate(high_parts)
    if verbose:
        print(f"[+] intersected seed candidates: {len(seed_highs)}", flush=True)

    rounds = 0
    for pair in LOW_FILTERS:
        if len(seed_highs) <= 200_000:
            break
        bit = common_zero_bit(np.unique(seed_lows), pair)
        if bit is None:
            continue
        rv = relation_high_vec(seed_lows, seed_highs, *pair)
        vals, counts = np.unique(rv, return_counts=True)
        if len(vals) <= 1:
            continue
        relation = find_known_high_relation(oracle, vals, counts, pair, bit)
        keep = rv == np.uint32(relation)
        seed_lows = seed_lows[keep]
        seed_highs = seed_highs[keep]
        rounds += 1
        if verbose:
            print(f"[+] high fixed filter {pair}: remain={len(seed_highs)}; queries={oracle.queries}", flush=True)

    while len(seed_highs) > 8 and rounds < 16:
        _, pair, bit, rv, vals, counts = choose_filter_pair(seed_lows, seed_highs)
        relation = find_known_high_relation(oracle, vals, counts, pair, bit)
        keep = rv == np.uint32(relation)
        seed_lows = seed_lows[keep]
        seed_highs = seed_highs[keep]
        rounds += 1
        if verbose:
            print(f"[+] high filter {pair}: remain={len(seed_highs)}; queries={oracle.queries}", flush=True)

    probe = bytes(320)
    expected = oracle.hash_one(probe)
    seeds = []
    for low_np, high_np in zip(seed_lows, seed_highs):
        seed = (int(high_np) << 32) | int(low_np)
        if xxh_hex(probe, seed) == expected:
            seeds.append(seed)
    if len(seeds) != 1:
        raise RuntimeError(f"seed validation produced {len(seeds)} candidates")
    return seeds[0]


# ---------------------------------------------------------------------------
# Invert one fold128(c, y) with a small lattice
# ---------------------------------------------------------------------------


def invert_fold_once(
    c: int,
    target: int,
    rng: random.Random,
    block: int,
    scale: int,
    marker: int,
    loops: int,
) -> int | None:
    if c == 0:
        return 0 if target == 0 else None

    n = 64
    dim = 66
    raw = [
        ((1 << j) * ((1 << 64) + 1 - 2 * ((target >> j) & 1))) % c
        for j in range(n)
    ]
    permutation = list(range(n))
    rng.shuffle(permutation)

    basis = IntegerMatrix(dim, dim)
    for row, bit in enumerate(permutation):
        basis[row, row] = 2
        lift = rng.randint(-3, 3)
        basis[row, 65] = scale * (raw[bit] + lift * c)
    for row in range(n):
        basis[64, row] = 1
    basis[64, 64] = marker
    basis[64, 65] = scale * ((-target) % c + rng.randint(-3, 3) * c)
    basis[65, 65] = scale * c

    LLL.reduction(basis, delta=0.999, eta=0.501)
    BKZ.reduction(
        basis,
        BKZ.Param(block_size=block, max_loops=loops, flags=BKZ.AUTO_ABORT),
    )

    for row_idx in range(dim):
        row = [int(basis[row_idx, col]) for col in range(dim)]
        for sign in (1, -1):
            v = [sign * x for x in row]
            if abs(v[64]) != marker or v[65] != 0:
                continue
            if not all(abs(v[i]) == 1 for i in range(64)):
                continue
            if v[64] == -marker:
                bits = [(v[i] + 1) // 2 for i in range(64)]
            else:
                bits = [(-v[i] + 1) // 2 for i in range(64)]
            high_product = 0
            for perm_idx, bit_value in enumerate(bits):
                high_product |= bit_value << permutation[perm_idx]
            numerator = high_product * (1 << 64) + (target ^ high_product)
            if numerator % c:
                continue
            y = numerator // c
            if y < (1 << 64) and fold128(c, y) == target:
                return y
    return None


def invert_fold(c: int, target: int, rng: random.Random, attempts: int = 12) -> int | None:
    for attempt in range(attempts):
        result = invert_fold_once(
            c,
            target,
            rng,
            block=20 + 2 * (attempt % 5),
            scale=1 << (8 + 2 * (attempt % 5)),
            marker=(1, 2, 4)[attempt % 3],
            loops=4 + (attempt % 3),
        )
        if result is not None:
            return result
    return None


def solve_pair_sum(c0: int, c1: int, target: int, rng: random.Random) -> tuple[int, int]:
    for _ in range(50):
        y0 = rng.getrandbits(64)
        remaining = (target - fold128(c0, y0)) & MASK64
        y1 = invert_fold(c1, remaining, rng, attempts=5)
        if y1 is not None:
            assert (fold128(c0, y0) + fold128(c1, y1)) & MASK64 == target
            return y0, y1
    raise RuntimeError("failed to invert fold128 pair sum")


def target_accumulators(seed: int, rng: random.Random) -> list[int]:
    secret = custom_secret(seed)
    target_high = int.from_bytes(TARGET[:8], "big")
    target_low = int.from_bytes(TARGET[8:], "big")
    pre_low = inverse_avalanche(target_low)
    pre_high = inverse_avalanche(target_high)
    need_low = (pre_low - 320 * P64_1) & MASK64
    need_high = (pre_high - ((~(320 * P64_2)) & MASK64)) & MASK64

    low_keys = [
        (u64(secret, 11 + 16*i), u64(secret, 19 + 16*i))
        for i in range(4)
    ]
    high_keys = [
        (u64(secret, 117 + 16*i), u64(secret, 125 + 16*i))
        for i in range(4)
    ]

    acc = [0] * 8
    c0 = high_keys[0][0] ^ low_keys[0][0]
    c1 = high_keys[1][0] ^ low_keys[1][0]
    y0, y1 = solve_pair_sum(c0, c1, need_low, rng)
    for pair_index, y in ((0, y0), (1, y1)):
        acc[2*pair_index] = high_keys[pair_index][0]
        acc[2*pair_index+1] = low_keys[pair_index][1] ^ y

    c2 = low_keys[2][0] ^ high_keys[2][0]
    c3 = low_keys[3][0] ^ high_keys[3][0]
    y2, y3 = solve_pair_sum(c2, c3, need_high, rng)
    for pair_index, y in ((2, y2), (3, y3)):
        acc[2*pair_index] = low_keys[pair_index][0]
        acc[2*pair_index+1] = high_keys[pair_index][1] ^ y

    # Exact merge verification.
    low = (320 * P64_1) & MASK64
    high = (~(320 * P64_2)) & MASK64
    for i in range(4):
        low = (low + fold128(acc[2*i] ^ low_keys[i][0], acc[2*i+1] ^ low_keys[i][1])) & MASK64
        high = (high + fold128(acc[2*i] ^ high_keys[i][0], acc[2*i+1] ^ high_keys[i][1])) & MASK64
    if low != pre_low or high != pre_high:
        raise RuntimeError("target accumulator merge verification failed")
    return acc


def build_payload(seed: int, desired_acc: list[int]) -> bytes:
    secret = custom_secret(seed)
    fixed = INIT_ACC.copy()
    # Stripes 2, 3 and the mandatory final stripe remain zero.
    for secret_offset in (16, 24, 121):
        for lane in range(8):
            key = u64(secret, secret_offset + 8*lane)
            fixed[lane] = (fixed[lane] + (key & MASK32) * (key >> 32)) & MASK64

    data = bytearray(320)
    for source_lane in range(8):
        target_lane = source_lane ^ 1
        needed_sum = (desired_acc[target_lane] - fixed[target_lane]) & MASK64
        key0 = u64(secret, 8*source_lane)
        key1 = u64(secret, 8 + 8*source_lane)
        key0_low = key0 & MASK32
        key1_high = key1 >> 32

        low1 = ((needed_sum & MASK32) - key0_low) & MASK32
        carry = (key0_low + low1) >> 32
        high0 = ((needed_sum >> 32) - key1_high - carry) & MASK32
        word0 = (high0 << 32) | key0_low
        word1 = (key1_high << 32) | low1

        # The product contribution in stripe 0/1 is zero by construction.
        assert ((word0 ^ key0) & MASK32) == 0
        assert ((word1 ^ key1) >> 32) == 0
        data[8*source_lane:8*source_lane+8] = word0.to_bytes(8, "little")
        data[64+8*source_lane:64+8*source_lane+8] = word1.to_bytes(8, "little")

    _, _, actual_acc = model_hash_320(bytes(data), seed)
    if actual_acc != desired_acc:
        raise RuntimeError("payload accumulator verification failed")
    if xxh_digest(bytes(data), seed) != TARGET:
        raise RuntimeError("payload digest verification failed")
    return bytes(data)


# ---------------------------------------------------------------------------
# Remote protocol
# ---------------------------------------------------------------------------


class RemoteOracle:
    POW_URL = "https://pwn.red/pow"

    def __init__(self, host: str, port: int):
        self.sock = socket.create_connection((host, port), timeout=15)
        self.sock.settimeout(120)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if hasattr(socket, "TCP_QUICKACK"):
            try:
                self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
            except OSError:
                pass
        self.buffer = b""
        self.queries = 0
        self._solve_pow()

    def _recv_until(self, marker: bytes) -> bytes:
        """Receive through marker while preserving bytes that follow it."""
        while True:
            pos = self.buffer.find(marker)
            if pos >= 0:
                end = pos + len(marker)
                data = self.buffer[:end]
                self.buffer = self.buffer[end:]
                return data

            chunk = self.sock.recv(65536)
            self._quick_ack()
            if not chunk:
                raise EOFError(
                    "remote closed the connection during the PoW handshake: "
                    + self.buffer.decode(errors="replace")
                )
            self.buffer += chunk

    def _solve_pow(self) -> None:
        """Solve the pwn.red proof-of-work challenge announced by the server."""
        banner = self._recv_until(b"solution:")
        text = banner.decode(errors="replace")
        print(text, end="", flush=True)

        match = re.search(
            r"curl\s+-sSfL\s+https://pwn\.red/pow\s*\|\s*sh\s+-s\s+(\S+)",
            text,
        )
        if match is None:
            raise RuntimeError(f"unsupported PoW banner:\n{text}")

        challenge = match.group(1)
        print(f"[*] Solving proof of work for challenge {challenge}", flush=True)

        try:
            downloader = subprocess.run(
                ["curl", "-sSfL", self.POW_URL],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            )
            solver = subprocess.run(
                ["sh", "-s", challenge],
                input=downloader.stdout,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("curl or sh is not installed") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("proof-of-work solver timed out") from exc
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode(errors="replace") if exc.stderr else ""
            raise RuntimeError(f"proof-of-work solver failed: {stderr}") from exc

        lines = [line.strip() for line in solver.stdout.splitlines() if line.strip()]
        if not lines:
            stderr = solver.stderr.decode(errors="replace")
            raise RuntimeError(f"proof-of-work solver returned no solution: {stderr}")

        solution = lines[-1]
        print(f"[+] PoW solution: {solution.decode(errors='replace')}", flush=True)
        self.sock.sendall(solution + b"\n")

    def _quick_ack(self) -> None:
        if hasattr(socket, "TCP_QUICKACK"):
            try:
                self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
            except OSError:
                pass

    def _receive_hashes(self, count: int) -> list[str]:
        marker = b"[+] Hash: "
        found: list[str] = []
        while len(found) < count:
            while True:
                pos = self.buffer.find(marker)
                if pos < 0 or len(self.buffer) < pos + len(marker) + 32:
                    break
                value = self.buffer[pos + len(marker):pos + len(marker) + 32]
                if all(c in b"0123456789abcdef" for c in value):
                    found.append(value.decode())
                    self.buffer = self.buffer[pos + len(marker) + 32:]
                    if len(found) == count:
                        return found
                else:
                    self.buffer = self.buffer[pos + 1:]
            chunk = self.sock.recv(1 << 20)
            self._quick_ack()
            if not chunk:
                raise EOFError("remote closed the connection")
            self.buffer += chunk
        return found

    def hash_many(self, payloads: list[bytes]) -> list[str]:
        if not payloads:
            return []
        request = bytearray()
        for payload in payloads:
            request += b"1\n" + payload.hex().encode() + b"\n"

        send_errors: list[BaseException] = []

        def sender() -> None:
            try:
                self.sock.sendall(request)
            except BaseException as exc:  # propagated after receive unblocks
                send_errors.append(exc)

        thread = threading.Thread(target=sender, daemon=True)
        thread.start()
        result = self._receive_hashes(len(payloads))
        thread.join()
        if send_errors:
            raise send_errors[0]
        self.queries += len(payloads)
        return result

    def hash_one(self, payload: bytes) -> str:
        return self.hash_many([payload])[0]

    def submit(self, payload: bytes) -> str:
        self.sock.sendall(b"2\n" + payload.hex().encode() + b"\n")
        data = self.buffer
        self.buffer = b""
        self.sock.settimeout(20)
        while True:
            match = re.search(rb"SEKAI\{[^\r\n}]*\}", data)
            if match:
                return match.group().decode()
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout as exc:
                raise RuntimeError(data.decode(errors="replace")) from exc
            if not chunk:
                raise RuntimeError(data.decode(errors="replace"))
            data += chunk


class LocalOracle:
    def __init__(self, seed: int):
        self.seed = seed
        self.queries = 0

    def hash_many(self, payloads: list[bytes]) -> list[str]:
        self.queries += len(payloads)
        return [xxh_hex(payload, self.seed) for payload in payloads]

    def hash_one(self, payload: bytes) -> str:
        return self.hash_many([payload])[0]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default="iihash.chals.sekai.team")
    parser.add_argument("port", nargs="?", type=int, default=1337)
    parser.add_argument("--local-seed", type=lambda x: int(x, 0), help="run a local end-to-end self-test")
    args = parser.parse_args()

    started = time.time()
    if args.local_seed is not None:
        oracle = LocalOracle(args.local_seed & MASK64)
    else:
        print(f"[*] Connecting to {args.host}:{args.port}", flush=True)
        oracle = RemoteOracle(args.host, args.port)

    seed = recover_seed(oracle, verbose=True)
    print(f"[+] Recovered seed: {seed:#018x}", flush=True)

    rng = random.Random(seed)
    desired_acc = target_accumulators(seed, rng)
    payload = build_payload(seed, desired_acc)
    print(f"[+] Preimage ready: {len(payload)} bytes", flush=True)
    print(f"[+] Local digest: {xxh_digest(payload, seed)!r}", flush=True)

    if args.local_seed is not None:
        assert seed == (args.local_seed & MASK64)
        print(f"[+] Self-test passed in {time.time() - started:.2f}s with {oracle.queries} queries")
        return

    flag = oracle.submit(payload)
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
