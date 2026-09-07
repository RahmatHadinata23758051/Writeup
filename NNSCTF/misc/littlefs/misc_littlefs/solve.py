#!/usr/bin/env python3
from pathlib import Path
import bisect
import re
import struct

BASE = Path(__file__).resolve().parent
CAPTURE = BASE / "littlefs.logicdata"

# Channel block offsets in the Logic 1.x .logicdata save.
# The index table after each data stream contains 32-byte checkpoint records.
SECTIONS = {
    "ch0": {"data": 0x235,   "index": 0x8E1,   "records": 274},
    "ch1": {"data": 0x2B4D,  "index": 0x2C1C,  "records": 12},
    "ch2": {"data": 0x2DC5,  "index": 0x6D60,  "records": 1715},
    "ch3": {"data": 0x143E6, "index": 0x14601, "records": 76},
}

# The prompt says ch0=MOSI, ch1=CS, ch2=SCK, ch3=MISO.
# In the saved stream, the direction is effectively swapped for the two data
# channels; using ch3 as MOSI reveals normal SPI NOR commands: AB, 05, 9F, 03.
MOS_BUF = "ch3"
MISO_BUF = "ch0"
SCK_BUF = "ch2"


def byte_state(x: int) -> int:
    # High bit marks low level; low 7 bits are the delta to the next checkpoint.
    return 0 if (x & 0x80) else 1


def make_anchors(blob: bytes, name: str):
    sec = SECTIONS[name]
    out = []
    for i in range(sec["records"]):
        t, a, c, typ = struct.unpack_from("<QQQQ", blob, sec["index"] + 32 * i)
        if typ == 1:
            # Boundary before byte offset a.
            out.append((t, a))
        elif typ in (2, 3):
            # Boundary after byte offset c.
            out.append((t, c + 1))
    return sorted(out)


def build_wave(blob: bytes, name: str):
    sec = SECTIONS[name]
    start = sec["data"]
    anchors = make_anchors(blob, name)
    transitions = []
    cur_t = None
    cur_off = None
    cur_state = None

    def start_chunk(t: int, off: int):
        nonlocal cur_t, cur_off, cur_state
        target = byte_state(blob[start + off]) if start + off < sec["index"] else 1
        cur_state = 1 - target
        transitions.append((t, cur_state))
        cur_t = t
        cur_off = off

    for t, off in anchors:
        if cur_t is None or off <= cur_off:
            start_chunk(t, off)
            continue

        for k in range(cur_off, off):
            x = blob[start + k]
            cur_t += x & 0x7F
            st = byte_state(x)
            if st != cur_state:
                transitions.append((cur_t, st))
                cur_state = st

        # If the checkpoint has a larger timestamp than the delta stream, that is
        # an idle gap/new burst. Start a new burst at the checkpoint.
        if cur_t != t:
            start_chunk(t, off)
        else:
            cur_off = off

    transitions.sort()
    cleaned = []
    for t, st in transitions:
        if cleaned and cleaned[-1][0] == t:
            cleaned[-1] = (t, st)
        elif not cleaned or cleaned[-1][1] != st:
            cleaned.append((t, st))
    return cleaned


def level_at(wave, t: int, default: int = 0, before: bool = True) -> int:
    times = [x[0] for x in wave]
    idx = (bisect.bisect_left(times, t) if before else bisect.bisect_right(times, t)) - 1
    if idx < 0:
        return default
    return wave[idx][1]


def pack_bits(bits):
    out = bytearray()
    for i in range(0, len(bits) // 8 * 8, 8):
        v = 0
        for bit in bits[i:i + 8]:
            v = (v << 1) | bit
        out.append(v)
    return bytes(out)


def sck_clusters(waves):
    edges = []
    prev = 0
    for t, st in waves[SCK_BUF]:
        edges.append((t, prev, st))
        prev = st

    clusters = []
    cur = []
    for edge in edges:
        if cur and edge[0] - cur[-1][0] > 500:
            clusters.append(cur)
            cur = []
        cur.append(edge)
    if cur:
        clusters.append(cur)
    return clusters


def decode_spi(waves):
    tx = []
    for cluster in sck_clusters(waves):
        mosi_bits = []
        miso_bits = []
        for t, before, after in cluster:
            # SPI mode 0: sample on rising edge, MSB first.
            if before == 0 and after == 1:
                mosi_bits.append(level_at(waves[MOS_BUF], t, default=0, before=True))
                miso_bits.append(level_at(waves[MISO_BUF], t, default=0, before=True))
        tx.append((pack_bits(mosi_bits), pack_bits(miso_bits)))
    return tx


def reconstruct_flash(tx, size=0x10000):
    flash = bytearray(b"\xff" * size)
    reads = []
    i = 0
    commands = {0x03, 0x0B, 0x05, 0x06, 0x9F, 0xAB, 0xB9, 0x66, 0x99}

    while i < len(tx):
        mosi, miso = tx[i]
        if len(mosi) >= 4 and mosi[0] == 0x03:
            addr = (mosi[1] << 16) | (mosi[2] << 8) | mosi[3]
            data = bytearray(miso[4:])
            j = i + 1
            while j < len(tx):
                mo2, mi2 = tx[j]
                if mo2 and mo2[0] in commands:
                    break
                if mo2 and all(x == 0 for x in mo2):
                    data.extend(mi2)
                    j += 1
                    continue
                break
            if data:
                flash[addr:addr + len(data)] = data
                reads.append((addr, len(data)))
                i = j
                continue
        i += 1
    return bytes(flash), reads


def main():
    if not CAPTURE.exists():
        raise SystemExit(f"missing capture: {CAPTURE}")

    blob = CAPTURE.read_bytes()
    waves = {name: build_wave(blob, name) for name in SECTIONS}
    tx = decode_spi(waves)
    flash, reads = reconstruct_flash(tx)

    m = re.search(rb"NNS\{[\x20-\x7e]+?\}", flash)
    if not m:
        stream = b"".join(miso for _, miso in tx)
        m = re.search(rb"NNS\{[\x20-\x7e]+?\}", stream)

    print(f"decoded SPI bursts: {len(tx)}")
    print(f"reconstructed READ ranges: {len(reads)}")
    if not m:
        raise SystemExit("flag pattern not found")

    flag = m.group().decode("ascii")
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
