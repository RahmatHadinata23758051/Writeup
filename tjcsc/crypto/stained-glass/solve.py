#!/usr/bin/env python3
from pathlib import Path
import re
import struct
import zlib

PERIODS = (10, 6, 14)
RAW_W, RAW_H = 52, 48
KNOWN_PNG_PREFIX = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"


def parse_png(data: bytes) -> bool:
    """Strict enough PNG parser: signature, chunk sizes, and CRCs."""
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return False
    pos = 8
    seen_ihdr = False
    while pos + 12 <= len(data):
        length = int.from_bytes(data[pos:pos + 4], "big")
        ctype = data[pos + 4:pos + 8]
        start = pos + 8
        end = start + length
        crc_end = end + 4
        if length < 0 or crc_end > len(data):
            return False
        chunk_for_crc = data[pos + 4:end]
        want_crc = int.from_bytes(data[end:crc_end], "big")
        got_crc = zlib.crc32(chunk_for_crc) & 0xffffffff
        if got_crc != want_crc:
            return False
        if ctype == b"IHDR":
            if seen_ihdr or length != 13:
                return False
            seen_ihdr = True
        if ctype == b"IEND":
            return seen_ihdr and crc_end == len(data)
        pos = crc_end
    return False


def find_periodic_brush(raw: bytes) -> tuple[int, int, list[dict[int, int]]]:
    """
    The file is raw 52x48 RGB. One overpainted brush is visible as a long
    interval where R/G/B bytes repeat independently with periods 10, 6, 14.
    Recover that periodic XOR brush from the first longest such interval.
    """
    pixels = [raw[i:i + 3] for i in range(0, len(raw), 3)]
    best = None

    for start in range(len(pixels)):
        maps = [dict() for _ in PERIODS]
        end = start
        for i in range(start, len(pixels)):
            px = pixels[i]
            ok = True
            for channel, period in enumerate(PERIODS):
                residue = i % period
                value = px[channel]
                if residue in maps[channel] and maps[channel][residue] != value:
                    ok = False
                    break
            if not ok:
                break
            for channel, period in enumerate(PERIODS):
                maps[channel][i % period] = px[channel]
            end = i + 1

        run_len = end - start
        if run_len >= 80 and (best is None or run_len > best[1] - best[0]):
            best = (start, end, maps)

    if best is None:
        raise RuntimeError("periodic RGB brush was not found")

    start, end, maps = best
    for channel, period in enumerate(PERIODS):
        if len(maps[channel]) != period:
            raise RuntimeError("periodic brush did not cover every residue")
    return start, end, maps


def remove_periodic_brush(raw: bytes, maps: list[dict[int, int]]) -> bytes:
    out = bytearray(raw)
    pixels = len(raw) // 3
    for i in range(pixels):
        for channel, period in enumerate(PERIODS):
            out[3 * i + channel] ^= maps[channel][i % period]
    return bytes(out)


def recover_png(after_first_brush: bytes) -> bytes:
    """
    After the RGB brush is removed, the first bytes differ from the PNG magic
    by a repeating XOR key. Recover the shortest consistent key and verify PNG.
    """
    for key_len in range(1, 33):
        key = [None] * key_len
        ok = True
        for i, want in enumerate(KNOWN_PNG_PREFIX):
            k = after_first_brush[i] ^ want
            r = i % key_len
            if key[r] is not None and key[r] != k:
                ok = False
                break
            key[r] = k
        if not ok or any(k is None for k in key):
            continue
        key_bytes = bytes(key)
        candidate = bytes(b ^ key_bytes[i % key_len] for i, b in enumerate(after_first_brush))
        if parse_png(candidate):
            return candidate
    raise RuntimeError("valid PNG layer was not recovered")


def main() -> None:
    raw = Path("window.bin").read_bytes()
    if len(raw) != RAW_W * RAW_H * 3:
        raise RuntimeError(f"unexpected raw size: {len(raw)}")

    _, _, brush = find_periodic_brush(raw)
    stage1 = remove_periodic_brush(raw, brush)
    png = recover_png(stage1)

    # The decoded PNG displays mirrored text. The readable flag is:
    flag = "tjctf{three_keys_one_window}"

    # Sanity check the flag string and the decoded file type.
    assert parse_png(png)
    assert re.fullmatch(r"tjctf\{[A-Za-z0-9_]+\}", flag)
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
