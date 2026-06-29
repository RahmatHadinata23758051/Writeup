#!/usr/bin/env python3
"""TraceBash CTF - Frequency Trap solver.

Usage:
    python3 solve.py frequency_trap.png
    python3 solve.py frequency_trap.png --verbose
    python3 solve.py frequency_trap.png --deep

Dependencies:
    pip install pillow numpy scipy

The original PNG is required. A resized preview changes the 8x8 DCT blocks and
cannot be decoded reliably.
"""

from __future__ import annotations

import argparse
import base64
import bz2
import gzip
import hashlib
import io
import json
import lzma
import random
import re
import shutil
import struct
import subprocess
import sys
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

import numpy as np
from PIL import ExifTags, Image
from scipy.fft import dctn

FLAG_RE = re.compile(rb"(?:TBCTF|[A-Za-z0-9_]{2,20}CTF)\{[^}\r\n]{1,200}\}")
BF_OPS = set("><+-.,[]")


@dataclass(frozen=True)
class Metadata:
    method: str
    lens_model: str


@dataclass(frozen=True)
class Hit:
    flag: bytes
    path: str


def brainfuck(program: str) -> bytes:
    code = "".join(ch for ch in program if ch in BF_OPS)
    jumps: dict[int, int] = {}
    stack: list[int] = []

    for i, op in enumerate(code):
        if op == "[":
            stack.append(i)
        elif op == "]":
            if not stack:
                raise ValueError("unmatched ']' in Brainfuck program")
            left = stack.pop()
            jumps[left] = i
            jumps[i] = left
    if stack:
        raise ValueError("unmatched '[' in Brainfuck program")

    tape = [0] * 30000
    ptr = pc = 0
    out = bytearray()

    while pc < len(code):
        op = code[pc]
        if op == ">":
            ptr += 1
            if ptr == len(tape):
                tape.append(0)
        elif op == "<":
            ptr = max(0, ptr - 1)
        elif op == "+":
            tape[ptr] = (tape[ptr] + 1) & 0xFF
        elif op == "-":
            tape[ptr] = (tape[ptr] - 1) & 0xFF
        elif op == ".":
            out.append(tape[ptr])
        elif op == "[" and tape[ptr] == 0:
            pc = jumps[pc]
        elif op == "]" and tape[ptr] != 0:
            pc = jumps[pc]
        pc += 1

    return bytes(out)


def read_metadata(path: Path) -> Metadata:
    method = ""
    lens_model = ""

    if shutil.which("exiftool"):
        try:
            proc = subprocess.run(
                ["exiftool", "-j", str(path)],
                check=True,
                capture_output=True,
                text=True,
            )
            record = json.loads(proc.stdout)[0]
            method = str(record.get("ImageDescription", ""))
            lens_model = str(record.get("LensModel", ""))
        except (subprocess.SubprocessError, json.JSONDecodeError, IndexError):
            pass

    if not method or not lens_model:
        try:
            with Image.open(path) as image:
                exif = image.getexif()
                tags = {ExifTags.TAGS.get(tag, str(tag)): value for tag, value in exif.items()}
                method = method or str(tags.get("ImageDescription", ""))
                lens_model = lens_model or str(tags.get("LensModel", ""))
        except Exception:
            pass

    return Metadata(method=method, lens_model=lens_model)


def luminance_variants(path: Path) -> Iterator[tuple[str, np.ndarray]]:
    with Image.open(path) as image:
        rgb_u8 = np.asarray(image.convert("RGB"), dtype=np.uint8)
        pil_y = np.asarray(image.convert("YCbCr"), dtype=np.float32)[:, :, 0]

    rgb = rgb_u8.astype(np.float32)
    y_float = 0.299 * rgb[:, :, 0] + 0.587 * rgb[:, :, 1] + 0.114 * rgb[:, :, 2]
    y_round = np.rint(y_float).clip(0, 255).astype(np.float32)

    yield "Pillow YCbCr", pil_y
    yield "BT.601 rounded", y_round
    yield "BT.601 float", y_float


def calculate_dct(y: np.ndarray) -> np.ndarray:
    block = 8
    rows = y.shape[0] // block
    cols = y.shape[1] // block
    cropped = y[: rows * block, : cols * block]
    blocks = cropped.reshape(rows, block, cols, block).transpose(0, 2, 1, 3)
    return dctn(blocks - 128.0, axes=(-2, -1), norm="ortho")


def coefficient_bitplanes(coefficients: np.ndarray, deep: bool) -> Iterator[tuple[str, np.ndarray]]:
    # "coeff3x3" can mean array index [3,3] or the third coefficient [2,2].
    for u, v in ((3, 3), (2, 2)):
        c = coefficients[:, :, u, v]
        yield f"coeff({u},{v}) sign", c >= 0
        yield f"coeff({u},{v}) rounded parity", np.rint(c).astype(np.int64) & 1
        yield f"coeff({u},{v}) absolute rounded parity", np.rint(np.abs(c)).astype(np.int64) & 1
        yield f"coeff({u},{v}) absolute floor parity", np.floor(np.abs(c)).astype(np.int64) & 1

        steps = (2, 4, 8, 10, 16) if not deep else range(1, 33)
        for step in steps:
            bits = np.rint(np.abs(c) / float(step)).astype(np.int64) & 1
            yield f"coeff({u},{v}) QIM step={step}", bits

        if deep:
            for du, dv in ((0, 1), (1, 0), (0, -1), (-1, 0), (1, 1), (-1, -1)):
                uu, vv = u + du, v + dv
                if not (0 <= uu < 8 and 0 <= vv < 8):
                    continue
                other = coefficients[:, :, uu, vv]
                yield f"abs({u},{v}) > abs({uu},{vv})", np.abs(c) > np.abs(other)
                yield f"({u},{v}) > ({uu},{vv})", c > other


def flatten_plane(plane: np.ndarray, order: str) -> np.ndarray:
    matrix = np.asarray(plane, dtype=np.uint8)
    if order == "row":
        return matrix.ravel()
    if order == "column":
        return matrix.T.ravel()
    if order == "snake":
        copy = matrix.copy()
        copy[1::2] = copy[1::2, ::-1]
        return copy.ravel()
    if order == "row-reverse":
        return matrix.ravel()[::-1]
    if order == "column-reverse":
        return matrix.T.ravel()[::-1]
    if order == "column-snake":
        copy = matrix.T.copy()
        copy[1::2] = copy[1::2, ::-1]
        return copy.ravel()
    raise ValueError(order)


def password_permutations(length: int, password: bytes) -> Iterator[tuple[str, np.ndarray | None]]:
    yield "natural", None
    if not password:
        return

    digest = hashlib.sha256(password).digest()
    seeds = {
        "sha256-be": int.from_bytes(digest[:4], "big"),
        "sha256-le": int.from_bytes(digest[:4], "little"),
        "md5-be": int.from_bytes(hashlib.md5(password).digest()[:4], "big"),
        "crc32": zlib.crc32(password),
        "byte-sum": sum(password),
    }

    for name, seed in seeds.items():
        yield f"numpy-default_rng-{name}", np.random.default_rng(seed).permutation(length)
        yield f"numpy-RandomState-{name}", np.random.RandomState(seed).permutation(length)

    indexes = list(range(length))
    random.Random(password.decode(errors="ignore")).shuffle(indexes)
    yield "python-random-string", np.asarray(indexes, dtype=np.int64)


def pack_bits(bits: np.ndarray, bit_offset: int, bit_order: str, invert: bool) -> bytes:
    data = np.asarray(bits, dtype=np.uint8)
    if invert:
        data = data ^ 1
    data = data[bit_offset:]
    data = data[: (len(data) // 8) * 8]
    if not len(data):
        return b""
    return np.packbits(data, bitorder=bit_order).tobytes()


def xor_repeat(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(value ^ key[i % len(key)] for i, value in enumerate(data))


def add_repeat(data: bytes, key: bytes, subtract: bool) -> bytes:
    if not key:
        return data
    if subtract:
        return bytes((value - key[i % len(key)]) & 0xFF for i, value in enumerate(data))
    return bytes((value + key[i % len(key)]) & 0xFF for i, value in enumerate(data))


def rc4(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]

    out = bytearray()
    i = j = 0
    for value in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out.append(value ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(out)


def direct_decodings(blob: bytes, password: bytes) -> Iterator[tuple[str, bytes]]:
    yield "raw", blob
    if not password:
        return

    yield "xor(password)", xor_repeat(blob, password)
    yield "subtract(password)", add_repeat(blob, password, subtract=True)
    yield "add(password)", add_repeat(blob, password, subtract=False)
    yield "RC4(password)", rc4(blob, password)

    for name, key in (
        ("MD5", hashlib.md5(password).digest()),
        ("SHA1", hashlib.sha1(password).digest()),
        ("SHA256", hashlib.sha256(password).digest()),
    ):
        yield f"xor({name}(password))", xor_repeat(blob, key)


def wrapped_decodings(label: str, blob: bytes, password: bytes) -> Iterator[tuple[str, bytes]]:
    yield label, blob

    # Common fixed-length header formats.
    if len(blob) >= 4:
        for name, fmt in (("uint32-be", ">I"), ("uint32-le", "<I")):
            size = struct.unpack(fmt, blob[:4])[0]
            if 0 < size <= len(blob) - 4:
                yield f"{label} -> {name}", blob[4 : 4 + size]

    stripped = blob.strip(b"\x00\r\n\t ")
    if stripped and stripped != blob:
        yield f"{label} -> strip", stripped

    # Decode text wrappers only when the entire stripped stream fits the alphabet.
    if len(stripped) >= 8 and re.fullmatch(rb"[A-Za-z0-9+/=_-]+", stripped):
        try:
            yield f"{label} -> base64", base64.b64decode(stripped, validate=False)
        except Exception:
            pass
    if len(stripped) >= 8 and len(stripped) % 2 == 0 and re.fullmatch(rb"[0-9A-Fa-f]+", stripped):
        try:
            yield f"{label} -> hex", bytes.fromhex(stripped.decode())
        except Exception:
            pass

    # Compression is attempted only when a matching header is present.
    decompressors = (
        (b"\x1f\x8b", "gzip", gzip.decompress),
        (b"BZh", "bz2", bz2.decompress),
        (b"\xfd7zXZ\x00", "lzma", lzma.decompress),
        (b"x\x01", "zlib", zlib.decompress),
        (b"x\x9c", "zlib", zlib.decompress),
        (b"x\xda", "zlib", zlib.decompress),
    )
    for magic, name, function in decompressors:
        start = blob.find(magic)
        if start < 0:
            continue
        try:
            yield f"{label} -> {name}", function(blob[start:])
        except Exception:
            pass

    # Python supports traditional ZipCrypto when a password is supplied.
    for match in list(re.finditer(re.escape(b"PK\x03\x04"), blob[:65536]))[:4]:
        try:
            with zipfile.ZipFile(io.BytesIO(blob[match.start() :])) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    try:
                        member = archive.read(info, pwd=password or None)
                    except Exception:
                        continue
                    yield f"{label} -> zip:{info.filename}", member
        except Exception:
            pass


def inspect_blob(blob: bytes, password: bytes) -> Hit | None:
    seen: set[bytes] = set()
    queue: list[tuple[str, bytes, int]] = [
        (label, data, 0) for label, data in direct_decodings(blob, password)
    ]

    while queue:
        label, data, depth = queue.pop(0)
        digest = hashlib.sha256(data).digest()
        if digest in seen:
            continue
        seen.add(digest)

        match = FLAG_RE.search(data)
        if match:
            return Hit(match.group(0), label)

        if depth >= 2:
            continue
        for next_label, decoded in wrapped_decodings(label, data, password):
            if decoded != data:
                queue.append((next_label, decoded, depth + 1))

    return None


def candidate_streams(
    plane: np.ndarray,
    password: bytes,
    stage: str,
) -> Iterator[tuple[str, bytes]]:
    if stage == "hinted":
        orders = ("row",)
        use_permutations = False
        offsets = (0,)
    elif stage == "password":
        orders = ("row", "snake", "column")
        use_permutations = True
        offsets = (0,)
    else:
        orders = ("row", "snake", "column", "row-reverse", "column-reverse", "column-snake")
        use_permutations = True
        offsets = range(8)

    for order in orders:
        flat = flatten_plane(plane, order)
        permutations: Iterable[tuple[str, np.ndarray | None]]
        if use_permutations:
            permutations = password_permutations(len(flat), password)
        else:
            permutations = (("natural", None),)

        for permutation_name, permutation in permutations:
            selected = flat if permutation is None else flat[permutation]
            for invert in (False, True):
                for offset in offsets:
                    for bit_order in ("big", "little"):
                        packed = pack_bits(selected, offset, bit_order, invert)
                        label = (
                            f"order={order}; permutation={permutation_name}; invert={invert}; "
                            f"bit-offset={offset}; bit-order={bit_order}"
                        )
                        yield label, packed


def solve(path: Path, password: bytes, deep: bool, verbose: bool) -> Hit | None:
    stages = ["hinted", "password"]
    if deep:
        stages.append("deep")

    for y_name, y in luminance_variants(path):
        coefficients = calculate_dct(y)
        if verbose:
            rows, cols = coefficients.shape[:2]
            print(f"[*] {y_name}: {cols} x {rows} DCT blocks", file=sys.stderr)

        planes = list(coefficient_bitplanes(coefficients, deep=deep))
        for stage in stages:
            if verbose:
                print(f"[*] Stage: {stage}", file=sys.stderr)
            for plane_name, plane in planes:
                for stream_name, blob in candidate_streams(plane, password, stage):
                    hit = inspect_blob(blob, password)
                    if hit:
                        return Hit(
                            hit.flag,
                            f"{y_name}; {plane_name}; {stream_name}; decode={hit.path}",
                        )
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract the Frequency Trap flag")
    parser.add_argument("image", nargs="?", default="frequency_trap.png", type=Path)
    parser.add_argument("--password", help="override the password stored as Brainfuck in LensModel")
    parser.add_argument("--deep", action="store_true", help="try slower compatibility variants")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.image.is_file():
        print(f"[-] File not found: {args.image}", file=sys.stderr)
        return 1

    metadata = read_metadata(args.image)
    if args.verbose:
        print(f"[*] ImageDescription: {metadata.method or '<missing>'}", file=sys.stderr)
        print(f"[*] LensModel: {metadata.lens_model or '<missing>'}", file=sys.stderr)

    if args.password is not None:
        password = args.password.encode()
    elif metadata.lens_model and any(ch in BF_OPS for ch in metadata.lens_model):
        password = brainfuck(metadata.lens_model)
    else:
        print("[-] Brainfuck password was not found in LensModel. Use --password.", file=sys.stderr)
        return 1

    if args.verbose:
        print(f"[*] Password: {password.decode(errors='replace')}", file=sys.stderr)

    hit = solve(args.image, password, args.deep, args.verbose)
    if not hit:
        print("[-] Flag was not recovered.", file=sys.stderr)
        print("[-] Make sure the input is the original 2500x1996 PNG, not a resized preview.", file=sys.stderr)
        print("[-] Retry with --deep for additional coefficient and traversal variants.", file=sys.stderr)
        return 2

    if args.verbose:
        print(f"[+] Extraction path: {hit.path}", file=sys.stderr)
    print(f"<FLAG>{hit.flag.decode(errors='replace')}</FLAG>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
