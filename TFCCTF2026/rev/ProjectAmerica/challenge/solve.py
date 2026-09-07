#!/usr/bin/env python3
from pathlib import Path
import base64
import gzip
import hashlib
import hmac
import re
import struct

MASK32 = 0xffffffff
MASK64 = (1 << 64) - 1
CID = b"AMERICAS-20dbcdd7061b4ccabfe947ef"


def u32(x):
    return x & MASK32


def rol32(x, n):
    n &= 31
    x &= MASK32
    return x if n == 0 else (((x << n) & MASK32) | (x >> (32 - n)))


def rol8(x, n):
    n &= 7
    x &= 0xff
    return x if n == 0 else (((x << n) & 0xff) | (x >> (8 - n)))


def rol64(x, n):
    n &= 63
    x &= MASK64
    return x if n == 0 else (((x << n) & MASK64) | (x >> (64 - n)))


def hash_parts(*parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(struct.pack("<I", len(part)))
        h.update(part)
    return h.digest()


def stream_xor(src, key):
    seed = hash_parts(b"TFCCTF/americas/stream/v1", key)
    state = struct.unpack("<Q", seed[:8])[0] | 1
    out = bytearray(len(src))
    for i, b in enumerate(src):
        if (i & 0x3f) == 0:
            state = rol64((((i + 1) * 0x9e3779b97f4a7c15) & MASK64) ^ state, 23)
        x = state
        x ^= (x << 13) & MASK64
        x ^= x >> 7
        x ^= (x << 17) & MASK64
        state = x & MASK64
        out[i] = b ^ ((state >> 29) & 0xff) ^ key[i % len(key)]
    return bytes(out)


def unpack_program(base: Path, cid: bytes):
    raw = (base / "content" / "patch_06.dat").read_bytes()
    assert raw.startswith(b"RPFVM01\n")
    encoded = base64.a85decode(raw[8:], adobe=False)
    key = hash_parts(b"Project-Americas/stage-1", cid)
    blob = gzip.decompress(stream_xor(encoded, key)[::-1])
    assert blob[:8] == b"MATHVM1\x00"
    count = struct.unpack("<H", blob[8:10])[0]
    assert blob[10:16] == hashlib.sha256(blob[16:]).digest()[:6]
    return [struct.unpack("<BBBBI", blob[16 + i * 8 : 24 + i * 8]) for i in range(count)]


def extract_root_secret(base: Path, cid: bytes):
    dlls = [
        "bin/rage_streaming_x64.dll",
        "bin/rgsc_socialclub_x64.dll",
        "bin/oo2core_9_win64.dll",
    ]
    parts = []
    for name in dlls:
        data = (base / name).read_bytes()
        pos = data.find(b"TFCSHARD/V1")
        assert pos >= 0, f"shard marker not found in {name}"
        marker_len = len(b"TFCSHARD/V1")
        role = data[pos + marker_len + 1]
        shard_len = data[pos + marker_len + 2]
        shard = data[pos + marker_len + 3 : pos + marker_len + 3 + shard_len]

        # The mask uses the full asset path string, not only the DLL basename.
        mask = hash_parts(
            b"Microsoft CodeView RSDS",
            cid,
            name.encode(),
            bytes([role]) + b"GTA",
        )
        parts.append(bytes(a ^ b for a, b in zip(shard, mask)))

    return bytes(parts[0][i] ^ parts[1][i] ^ parts[2][i] for i in range(32))


def run_program(program, state, counter):
    words = struct.unpack("<8I", state)
    regs = [u32((i * 0x6A09E667) ^ words[i] ^ counter) for i in range(8)]

    for pass_no in range(4):
        for idx, (op, a, b, c, imm) in enumerate(program):
            mix = u32((idx * 0x85EBCA6B) ^ imm ^ (pass_no * 0xC2B2AE35))
            if op == 1:
                regs[a] = u32(regs[a] + rol32(u32(regs[b] ^ mix), (mix ^ regs[c]) & 31))
            elif op == 2:
                regs[a] = u32(regs[a] ^ u32(regs[b] + rol32(mix, regs[c] & 31)))
            elif op == 3:
                regs[a] = u32(((regs[a] ^ regs[c]) * (regs[b] | 1)) + mix)
            elif op == 4:
                regs[a] = rol32(u32(regs[a] + mix), (regs[b] ^ regs[c]) & 31)
            elif op == 5:
                v = u32((mix ^ regs[b]) * 0xCC9E2D51)
                v = u32(rol32(v, 15) * 0x1B873593)
                regs[a] = u32(regs[a] ^ (v ^ regs[c]))
            elif op == 6:
                v = u32(mix ^ regs[b] ^ regs[c])
                regs[a] = u32(regs[a] ^ u32((v << 1) ^ (0x1B if (v & 0x80000000) else 0)))
            elif op == 7:
                t = u32(regs[a] + regs[c])
                regs[a] = u32(mix ^ regs[b])
                regs[b] = t
            else:
                raise ValueError(f"unknown VM opcode {op}")
    return struct.pack("<8I", *regs)


def derive_material(root_secret, cid, salt, program, size=0x60):
    state = hash_parts(b"TFCCTF/key-ladder/v4", root_secret, cid, salt)
    out = bytearray()
    counter = 0
    while len(out) < size:
        block = run_program(program, state, u32(counter ^ 0x564D0000))
        state = hash_parts(b"register-fold", state, block)
        out += state
        counter += 1
    return bytes(out[:size])


def round_keys(material):
    words = struct.unpack("<16I", material[:64])
    return [rol32(u32((i * 0x9E3779B9) ^ words[i & 15]), 11 * i) for i in range(36)]


def block_decrypt(block, keys):
    x0, x1, x2, x3 = struct.unpack("<4I", block)
    for i in range(35, -1, -1):
        # Invert blockEncrypt's (a,b,c,d) -> (b,c,d,a^f(b,c,d,i)).
        b, c, d, encrypted_a = x0, x1, x2, x3
        r10 = u32(keys[i] ^ d)
        r11 = u32((i * 0x9E3779B9) ^ r10)
        r11 = u32(r11 + b)
        r11 = rol32(r11, (c ^ r10) & 31)

        t = u32(rol32(r10, i) ^ c)
        t = u32(t * 0x7F4A7C15)
        t ^= r11
        t = u32(t * (((2 * i) ^ 0x85EBCA6B) | 1))
        t = u32((t ^ (t >> 16)) * 0xC2B2AE35)

        v = rol32(b ^ c, 7 * i) ^ t
        a = u32(encrypted_a ^ (v ^ (v >> 13)))
        x0, x1, x2, x3 = a, b, c, d
    return struct.pack("<4I", x0, x1, x2, x3)


def pkcs7_unpad(data):
    pad = data[-1]
    if not (1 <= pad <= 16) or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-pad]


def outer_mask(block_idx, j):
    return (((block_idx * 0x2F + 31 * j) ^ 0xA5) + rol8(13 * j, block_idx)) & 0xFF


def decrypt_outer(container, root_secret, cid, program):
    assert container[:8] == b"RSC\x07\xf1\x9aD\xc3"
    assert container[8:12] == b"\x04\x00\x30\x00"
    salt = b"RSC7/runtime-seal/" + container[0x0C:0x1C]
    ct_len = struct.unpack("<I", container[0x2C:0x30])[0]
    ct = container[0x30 : 0x30 + ct_len]
    tag = container[0x30 + ct_len : 0x30 + ct_len + 32]

    material = derive_material(root_secret, cid, salt, program, 0x60)
    expected = hmac.new(material[64:96], b"RSC7-AUTH-V4" + container[: 0x30 + ct_len], hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("outer HMAC mismatch")

    keys = round_keys(material)
    prev = container[0x1C:0x2C]
    out = bytearray()
    for off in range(0, ct_len, 16):
        cblk = ct[off : off + 16]
        dec = block_decrypt(cblk, keys)
        block_idx = off // 16
        for j, x in enumerate(dec):
            out.append(x ^ prev[j] ^ outer_mask(block_idx, j))
        prev = cblk
    return pkcs7_unpad(bytes(out))


def decrypt_inner(container, root_secret, cid, program):
    assert container[:8] == b"TFCENC3\x00"
    assert container[8:12] == b"\x03\x002\x00"
    aad_len = struct.unpack("<H", container[0x2C:0x2E])[0]
    ct_len = struct.unpack("<I", container[0x2E:0x32])[0]
    if len(container) != 0x52 + aad_len + ct_len:
        raise ValueError("bad inner container size")

    material = derive_material(root_secret, cid, container[0x0C:0x1C], program, 0x60)
    expected = hmac.new(material[64:96], container[:-32], hashlib.sha256).digest()
    if not hmac.compare_digest(expected, container[-32:]):
        raise ValueError("inner HMAC mismatch")

    keys = round_keys(material)
    ct_off = 0x32 + aad_len
    prev = container[0x1C:0x2C]
    out = bytearray()
    for off in range(0, ct_len, 16):
        cblk = container[ct_off + off : ct_off + off + 16]
        dec = block_decrypt(cblk, keys)
        block_idx = off // 16
        for j, x in enumerate(dec):
            out.append(x ^ prev[j] ^ ((block_idx * 0x1D + 17 * j) & 0xFF))
        prev = cblk
    return pkcs7_unpad(bytes(out))


def main():
    base = Path(__file__).resolve().parent
    program = unpack_program(base, CID)
    root_secret = extract_root_secret(base, CID)
    outer = (base / "challenge_data" / "flag.txt").read_bytes()
    inner = decrypt_outer(outer, root_secret, CID, program)
    plain = decrypt_inner(inner, root_secret, CID, program)

    match = re.search(rb"TFCCTF\{[^}]+\}", plain)
    if not match:
        raise SystemExit(f"flag pattern not found in plaintext: {plain!r}")
    flag = match.group(0).decode()
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
