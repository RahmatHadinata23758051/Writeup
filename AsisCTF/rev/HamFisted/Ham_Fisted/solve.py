#!/usr/bin/env python3
import os
import re
import random
import shutil
import subprocess
import wave
import zlib
import zipfile
from pathlib import Path
from collections import defaultdict

import numpy as np

FIXED_BINS = [51, 38, 25, 12]
DATA_BINS = [b for b in range(12, 52) if b not in FIXED_BINS]
GROUPS = [
    (0, 13800, 166),
    (1, 76078, 180),
    (2, 143593, 166),
    (3, 203680, 180),
    (4, 270404, 186),
]


def locate_files():
    here = Path.cwd()
    script_dir = Path(__file__).resolve().parent
    candidates = [here, script_dir, here / "Ham_Fisted", script_dir / "Ham_Fisted"]
    for d in candidates:
        if (d / "ham_fisted").exists() and (d / "capture.wav").exists():
            return d

    for d in [here, script_dir]:
        z = d / "Ham_Fisted.zip"
        if z.exists():
            out = d / "_ham_fisted_work"
            out.mkdir(exist_ok=True)
            with zipfile.ZipFile(z, "r") as f:
                f.extractall(out)
            for root, _, files in os.walk(out):
                p = Path(root)
                if "ham_fisted" in files and "capture.wav" in files:
                    return p
    raise FileNotFoundError("ham_fisted/capture.wav atau Ham_Fisted.zip tidak ditemukan")


ROOT = locate_files()
EXE = ROOT / "ham_fisted"
CAPTURE = ROOT / "capture.wav"
os.chmod(EXE, 0o755)

RAW_EXE = EXE.read_bytes()
CRC_TABLE = [int.from_bytes(RAW_EXE[0x41E0 + i * 2:0x41E2 + i * 2], "little") for i in range(256)]


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc = ((crc << 8) & 0xFFFF) ^ CRC_TABLE[((crc >> 8) ^ b) & 0xFF]
    return crc


def read_wav(path: Path) -> np.ndarray:
    with wave.open(str(path), "rb") as w:
        return np.frombuffer(w.readframes(w.getnframes()), dtype="<i2").astype(np.float64) / 32768.0


def lens_for(burst_idx: int):
    lens = []
    ec = 3 * burst_idx
    for ed in range(36):
        val = abs(ed - 17.5) / 17.5 + ((ec % 5) - 2) * 0.04
        if val < 0.34:
            a = 3
        elif val < 0.62:
            a = 2
        elif val < 0.86:
            a = 1
        else:
            a = 0
        lens.append([1, 2, 3, 4][a])
        ec += 7
    return lens


class CPScorer:
    def __init__(self, x: np.ndarray):
        L = 64
        prod = x[:-256] * x[256:]
        dot = np.convolve(prod, np.ones(L), "valid")
        s1 = np.convolve(x * x, np.ones(L), "valid")[:len(dot)]
        y = x[256:]
        s2 = np.convolve(y * y, np.ones(L), "valid")[:len(dot)]
        den = np.sqrt(s1 * s2)
        c = np.zeros_like(dot)
        np.divide(np.abs(dot), den, out=c, where=den > 0)
        self.c = c
        self.pref = []
        for r in range(320):
            a = c[r::320]
            self.pref.append(np.r_[0, np.cumsum(a)])

    def score(self, st: int, total: int) -> float:
        if st < 0 or st + (total - 1) * 320 >= len(self.c):
            return -1.0
        r = st % 320
        q = st // 320
        p = self.pref[r]
        if q + total > len(p) - 1:
            return -1.0
        return float((p[q + total] - p[q]) / total)

    def best(self, lo: int, hi: int, total: int):
        hi = min(hi, len(self.c) - (total - 1) * 320)
        best = (-1.0, None)
        for st in range(max(0, lo), max(0, hi)):
            sc = self.score(st, total)
            if sc > best[0]:
                best = (sc, st)
        return best


def extract_bins(x: np.ndarray, start: int, n_payload: int, bins):
    vals = []
    for sym in range(n_payload):
        st = start + (7 + sym) * 320
        if st + 320 > len(x):
            raise ValueError("symbol di luar file wav")
        freq = np.fft.rfft(x[st + 64:st + 320])
        vals.extend(freq[b] for b in bins)
    return np.array(vals)


def xor_whitening(bits):
    s = 0x1D74
    out = []
    for b in bits:
        pr = (s >> 16) & 1
        fb = ((s >> 11) ^ (s >> 16)) & 1
        s = ((s << 1) | fb) & 0x1FFFF
        out.append(b ^ pr)
    return out


def record_bits_for_reserved(body: bytes):
    rec = bytearray([0xAC, 0xE1, len(body)]) + bytearray(body)
    c = crc16(rec)
    rec += bytes([c >> 8, c & 0xFF])
    bits = [(b >> i) & 1 for b in rec for i in range(7, -1, -1)]
    return bits, bytes(rec)


def payload_labels(data: bytes, n_payload: int, lens):
    rec = bytearray(data)
    c = crc16(rec)
    rec += bytes([c >> 8, c & 0xFF])
    bits = [(b >> i) & 1 for b in rec for i in range(7, -1, -1)]
    total = n_payload * sum(lens)
    bits += [0] * max(0, total - len(bits))
    bits = xor_whitening(bits[:total])

    labels = []
    off = 0
    for _ in range(n_payload):
        for k, l in enumerate(lens):
            val = 0
            for bit in bits[off:off + l]:
                val = (val << 1) | bit
            labels.append((k, val))
            off += l
    return labels


def train_hidden(n_payload=159, body_len=59):
    rng = random.Random(2024)
    traffic = b"A" * 1914
    (ROOT / "_htraffic.bin").write_bytes(traffic)
    acc = defaultdict(complex)
    cnt = defaultdict(int)

    for r in range(40):
        body = bytes(rng.randrange(256) for _ in range(body_len))
        (ROOT / "_hres.bin").write_bytes(body)
        out = ROOT / f"_htrain_{r}.wav"
        subprocess.run([str(EXE), "_htraffic.bin", "_hres.bin", out.name], cwd=ROOT,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        x = read_wav(out)
        vals = extract_bins(x, 13800, n_payload, FIXED_BINS)
        bits, _ = record_bits_for_reserved(body)
        for idx, val in enumerate(vals):
            sym = idx // 4
            j = idx % 4
            pos = (sym + j * n_payload) % len(bits)
            b = bits[pos]
            acc[(idx, b)] += val
            cnt[(idx, b)] += 1
    return {k: acc[k] / cnt[k] for k in acc}


def recover_hidden(capture: np.ndarray, cent, n_payload=159, body_len=59):
    recbits = (body_len + 5) * 8
    vals = extract_bins(capture, 13800, n_payload, FIXED_BINS)
    bits = [None] * recbits
    margins = [-1.0] * recbits

    for idx, val in enumerate(vals):
        sym = idx // 4
        j = idx % 4
        pos = (sym + j * n_payload) % recbits
        if (idx, 0) not in cent or (idx, 1) not in cent:
            continue
        d0 = abs(val - cent[(idx, 0)])
        d1 = abs(val - cent[(idx, 1)])
        b = 0 if d0 < d1 else 1
        margin = abs(d0 - d1)
        if margin > margins[pos]:
            bits[pos] = b
            margins[pos] = margin

    known = bytes([0xAC, 0xE1, body_len])
    known_bits = [(b >> i) & 1 for b in known for i in range(7, -1, -1)]
    bits[:len(known_bits)] = known_bits
    if any(b is None for b in bits):
        raise RuntimeError("hidden bits tidak lengkap")

    def pack(bs):
        out = bytearray()
        for i in range(0, len(bs), 8):
            v = 0
            for bit in bs[i:i + 8]:
                v = (v << 1) | bit
            out.append(v)
        return bytes(out)

    rec = pack(bits)
    target_crc = (rec[-2] << 8) | rec[-1]
    if crc16(rec[:-2]) != target_crc:
        tmp = list(bits)
        for pos in range(len(known_bits), (body_len + 3) * 8):
            tmp[pos] ^= 1
            cand = pack(tmp)
            if crc16(cand[:-2]) == target_crc:
                rec = cand
                break
            tmp[pos] ^= 1

    if rec[:3] != known or crc16(rec[:-2]) != ((rec[-2] << 8) | rec[-1]):
        raise RuntimeError("hidden record gagal CRC")
    return rec[3:-2], rec


def run_segments(segs, prefix):
    traffic = ROOT / f"{prefix}_traffic.bin"
    reserved = ROOT / f"{prefix}_res.bin"
    outwav = ROOT / f"{prefix}.wav"
    traffic.write_bytes(b"\n%%\n".join(segs))
    reserved.write_bytes(bytes(range(59)))
    p = subprocess.run([str(EXE), traffic.name, reserved.name, outwav.name], cwd=ROOT,
                       capture_output=True, text=True, check=True)

    ns = []
    lengths = []
    for line in p.stderr.splitlines():
        m = re.search(r"burst (\d+): (\d+) B, (\d+) payload symbols", line)
        if m:
            lengths.append(int(m.group(2)))
            ns.append(int(m.group(3)))

    effective = [s + (b"\r\n" if i < len(segs) - 1 else b"") for i, s in enumerate(segs)]
    if [len(e) for e in effective] != lengths:
        raise RuntimeError("training length mismatch")

    x = read_wav(outwav)
    cp = CPScorer(x)
    starts = [13800]
    cur = 13800 + (7 + ns[0]) * 320 + 1000
    for i in range(1, len(ns)):
        score, st = cp.best(cur, cur + 30000, 7 + ns[i])
        if score < 0.75:
            raise RuntimeError("start training burst tidak ditemukan")
        starts.append(st)
        cur = st + (7 + ns[i]) * 320 + 1000
    return effective, ns, starts, x


def train_visible_for_burst(burst_idx: int, rounds=2):
    rng = random.Random(7000 + burst_idx)
    alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,;:/?=_+-[](){}<>!@#^&*"
    acc = defaultdict(complex)
    cnt = defaultdict(int)

    for r in range(rounds):
        segs = [bytes(rng.choice(alpha) for _ in range(4000 + i * 11 + r * 23))
                for i in range(burst_idx + 1)]
        eff, ns, starts, x = run_segments(segs, f"_vtrain_{burst_idx}_{r}")
        vals = extract_bins(x, starts[burst_idx], ns[burst_idx], DATA_BINS)
        labs = payload_labels(eff[burst_idx], ns[burst_idx], lens_for(burst_idx))
        for val, key in zip(vals, labs):
            acc[key] += val
            cnt[key] += 1

    cent = {k: acc[k] / cnt[k] for k in acc}
    for k, l in enumerate(lens_for(burst_idx)):
        for a in range(1 << l):
            if (k, a) not in cent:
                raise RuntimeError(f"centroid kurang untuk burst {burst_idx}, carrier {k}, label {a}")
    return cent


def decode_visible(capture, start, n_payload, burst_idx, cent):
    lens = lens_for(burst_idx)
    vals = extract_bins(capture, start, n_payload, DATA_BINS)
    whitened = []
    for idx, val in enumerate(vals):
        k = idx % 36
        l = lens[k]
        pred = min(range(1 << l), key=lambda a: abs(val - cent[(k, a)]))
        for bp in range(l - 1, -1, -1):
            whitened.append((pred >> bp) & 1)

    bits = xor_whitening(whitened)
    out = bytearray()
    for i in range(0, len(bits) // 8 * 8, 8):
        v = 0
        for bit in bits[i:i + 8]:
            v = (v << 1) | bit
        out.append(v)

    hits = []
    bit_sum = sum(lens)
    for L in range(1, len(out) - 2):
        if ((L + 2) * 8 + bit_sum - 1) // bit_sum != n_payload:
            continue
        if crc16(out[:L]) == ((out[L] << 8) | out[L + 1]):
            hits.append(bytes(out[:L]))
    return hits


def main():
    capture = read_wav(CAPTURE)

    hidden_centroids = train_hidden()
    hidden_body, hidden_record = recover_hidden(capture, hidden_centroids)
    if hidden_body[1] & 0x20 == 0:
        raise RuntimeError("zlib stream tidak meminta preset dictionary")
    wanted_adler = int.from_bytes(hidden_body[2:6], "big")

    visible_centroids = {bi: train_visible_for_burst(bi) for bi, _, _ in GROUPS}
    dictionary = None

    for bi, base, group_len in GROUPS:
        for shift in range(-3, 4):
            start = base + shift
            for n_payload in range(max(1, group_len - 15), group_len + 8):
                if start + (7 + n_payload) * 320 > len(capture):
                    continue
                for msg in decode_visible(capture, start, n_payload, bi, visible_centroids[bi]):
                    for line in msg.splitlines():
                        if zlib.adler32(line) & 0xFFFFFFFF == wanted_adler:
                            dictionary = line
                            break
                    if dictionary is not None:
                        break
                if dictionary is not None:
                    break
            if dictionary is not None:
                break
        if dictionary is not None:
            break

    if dictionary is None:
        raise RuntimeError("dictionary zlib tidak ditemukan di traffic")

    dec = zlib.decompressobj(wbits=15, zdict=dictionary)
    flag = dec.decompress(hidden_body) + dec.flush()
    print(flag.decode())


if __name__ == "__main__":
    main()
