#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import ipaddress
import os
import random
import re
import socket
import ssl
import struct
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

# RADIUS codes
ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
ACCESS_REJECT = 3
ACCESS_CHALLENGE = 11

# RADIUS attributes
ATTR_USER_NAME = 1
ATTR_NAS_IP_ADDRESS = 4
ATTR_NAS_PORT = 5
ATTR_FRAMED_MTU = 12
ATTR_REPLY_MESSAGE = 18
ATTR_STATE = 24
ATTR_CALLING_STATION_ID = 31
ATTR_NAS_IDENTIFIER = 32
ATTR_NAS_PORT_TYPE = 61
ATTR_EAP_MESSAGE = 79
ATTR_MESSAGE_AUTHENTICATOR = 80

# EAP codes / types
EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4
EAP_TYPE_IDENTITY = 1
EAP_TYPE_NAK = 3
EAP_TYPE_TLS = 13

# EAP-TLS flags
TLS_FLAG_LENGTH = 0x80
TLS_FLAG_MORE = 0x40
TLS_FLAG_START = 0x20

DEFAULT_SECRET = b"testing123"
FLAG_RE = re.compile(rb"NHNC\{[^}\r\n]+\}")


class SolveError(RuntimeError):
    pass


def p16(value: int) -> bytes:
    return struct.pack("!H", value)


def p32(value: int) -> bytes:
    return struct.pack("!I", value)


def radius_attr(attr_type: int, value: bytes) -> bytes:
    if len(value) > 253:
        raise ValueError(f"RADIUS attribute {attr_type} is too large")
    return bytes((attr_type, len(value) + 2)) + value


def split_eap_attributes(eap: bytes) -> Iterable[bytes]:
    for offset in range(0, len(eap), 253):
        yield radius_attr(ATTR_EAP_MESSAGE, eap[offset : offset + 253])


@dataclass
class RadiusPacket:
    code: int
    identifier: int
    authenticator: bytes
    attributes: list[tuple[int, bytes]]
    raw: bytes

    def values(self, attr_type: int) -> list[bytes]:
        return [value for current_type, value in self.attributes if current_type == attr_type]

    def eap(self) -> bytes:
        return b"".join(self.values(ATTR_EAP_MESSAGE))


@dataclass
class EapPacket:
    code: int
    identifier: int
    eap_type: Optional[int]
    data: bytes
    raw: bytes


@dataclass
class EapTlsPacket:
    flags: int
    total_length: Optional[int]
    tls_data: bytes


def parse_radius(data: bytes) -> RadiusPacket:
    if len(data) < 20:
        raise SolveError("short RADIUS packet")
    code, identifier, length = struct.unpack("!BBH", data[:4])
    if length < 20 or length > len(data):
        raise SolveError(f"invalid RADIUS length {length}")
    raw = data[:length]
    authenticator = raw[4:20]
    attrs: list[tuple[int, bytes]] = []
    offset = 20
    while offset < length:
        if offset + 2 > length:
            raise SolveError("truncated RADIUS attribute header")
        attr_type = raw[offset]
        attr_length = raw[offset + 1]
        if attr_length < 2 or offset + attr_length > length:
            raise SolveError("invalid RADIUS attribute length")
        attrs.append((attr_type, raw[offset + 2 : offset + attr_length]))
        offset += attr_length
    return RadiusPacket(code, identifier, authenticator, attrs, raw)


def parse_eap(data: bytes) -> EapPacket:
    if len(data) < 4:
        raise SolveError("short EAP packet")
    code, identifier, length = struct.unpack("!BBH", data[:4])
    if length < 4 or length > len(data):
        raise SolveError(f"invalid EAP length {length}")
    raw = data[:length]
    if code in (EAP_REQUEST, EAP_RESPONSE):
        if length < 5:
            raise SolveError("EAP request/response has no type")
        return EapPacket(code, identifier, raw[4], raw[5:], raw)
    return EapPacket(code, identifier, None, raw[4:], raw)


def parse_eap_tls(eap: EapPacket) -> EapTlsPacket:
    if eap.eap_type != EAP_TYPE_TLS or not eap.data:
        raise SolveError("not an EAP-TLS packet")
    flags = eap.data[0]
    offset = 1
    total_length: Optional[int] = None
    if flags & TLS_FLAG_LENGTH:
        if len(eap.data) < 5:
            raise SolveError("truncated EAP-TLS length")
        total_length = struct.unpack("!I", eap.data[1:5])[0]
        offset = 5
    return EapTlsPacket(flags, total_length, eap.data[offset:])


def make_eap(code: int, identifier: int, eap_type: int, data: bytes = b"") -> bytes:
    body = bytes((eap_type,)) + data
    return struct.pack("!BBH", code, identifier, len(body) + 4) + body


def make_eap_tls_response(
    identifier: int,
    payload: bytes = b"",
    *,
    flags: int = 0,
    total_length: Optional[int] = None,
) -> bytes:
    body = bytes((flags,))
    if flags & TLS_FLAG_LENGTH:
        if total_length is None:
            raise ValueError("EAP-TLS L flag requires total_length")
        body += p32(total_length)
    body += payload
    return make_eap(EAP_RESPONSE, identifier, EAP_TYPE_TLS, body)


class RadiusClient:
    def __init__(
        self,
        host: str,
        port: int,
        secret: bytes,
        identity: str,
        timeout: float,
        retries: int,
        framed_mtu: int,
    ) -> None:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
        if not infos:
            raise SolveError(f"cannot resolve {host}")
        family, socktype, proto, _, sockaddr = infos[0]
        self.sock = socket.socket(family, socktype, proto)
        self.sock.settimeout(timeout)
        self.sock.connect(sockaddr)
        self.secret = secret
        self.identity = identity.encode()
        self.retries = retries
        self.framed_mtu = framed_mtu
        self.identifier = random.randrange(256)
        self.calling_station = "02-%02X-%02X-%02X-%02X-%02X" % tuple(
            random.randrange(256) for _ in range(5)
        )

    def close(self) -> None:
        self.sock.close()

    def _build_request(self, identifier: int, request_auth: bytes, eap: bytes, states: list[bytes]) -> bytes:
        attrs = bytearray()
        attrs += radius_attr(ATTR_USER_NAME, self.identity)
        attrs += radius_attr(ATTR_NAS_PORT, p32(1))
        attrs += radius_attr(ATTR_FRAMED_MTU, p32(self.framed_mtu))
        attrs += radius_attr(ATTR_CALLING_STATION_ID, self.calling_station.encode())
        attrs += radius_attr(ATTR_NAS_IDENTIFIER, b"teagod-solver")
        attrs += radius_attr(ATTR_NAS_PORT_TYPE, p32(19))  # Wireless IEEE 802.11
        for state in states:
            attrs += radius_attr(ATTR_STATE, state)
        for part in split_eap_attributes(eap):
            attrs += part

        ma_offset_in_attrs = len(attrs) + 2
        attrs += radius_attr(ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16)
        length = 20 + len(attrs)
        packet = bytearray(struct.pack("!BBH", ACCESS_REQUEST, identifier, length) + request_auth + attrs)
        ma_offset = 20 + ma_offset_in_attrs
        digest = hmac.new(self.secret, bytes(packet), hashlib.md5).digest()
        packet[ma_offset : ma_offset + 16] = digest
        return bytes(packet)

    def _verify_response_authenticator(self, packet: RadiusPacket, request_auth: bytes) -> bool:
        expected = hashlib.md5(
            packet.raw[:4] + request_auth + packet.raw[20:] + self.secret
        ).digest()
        return hmac.compare_digest(expected, packet.authenticator)

    def exchange(self, eap: bytes, states: list[bytes]) -> RadiusPacket:
        radius_id = self.identifier
        self.identifier = (self.identifier + 1) & 0xFF
        request_auth = os.urandom(16)
        request = self._build_request(radius_id, request_auth, eap, states)

        last_error: Optional[Exception] = None
        for _ in range(self.retries + 1):
            try:
                self.sock.send(request)
                while True:
                    data = self.sock.recv(65535)
                    response = parse_radius(data)
                    if response.identifier != radius_id:
                        continue
                    if not self._verify_response_authenticator(response, request_auth):
                        raise SolveError("bad RADIUS response authenticator")
                    return response
            except socket.timeout as exc:
                last_error = exc
        raise SolveError(f"RADIUS timeout after {self.retries + 1} attempts") from last_error


class TlsEngine:
    def __init__(self, certfile: str, keyfile: str, key_password: Optional[str]) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.load_cert_chain(certfile=certfile, keyfile=keyfile, password=key_password)
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.ssl_object = context.wrap_bio(
            self.incoming,
            self.outgoing,
            server_side=False,
            server_hostname="radius.teagod.tech",
        )
        self.complete = False

    def feed(self, data: bytes) -> None:
        if data:
            self.incoming.write(data)

    def handshake(self) -> None:
        try:
            self.ssl_object.do_handshake()
            self.complete = True
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLWantWriteError:
            pass
        except ssl.SSLError as exc:
            raise SolveError(f"TLS handshake failed: {exc}") from exc

    def drain(self) -> bytes:
        chunks: list[bytes] = []
        while self.outgoing.pending:
            chunks.append(self.outgoing.read())
        return b"".join(chunks)


class EapTlsSolver:
    def __init__(self, radius: RadiusClient, tls: TlsEngine, fragment_size: int, verbose: bool) -> None:
        self.radius = radius
        self.tls = tls
        self.fragment_size = fragment_size
        self.verbose = verbose
        self.states: list[bytes] = []
        self.server_tls_buffer = bytearray()
        self.server_tls_expected: Optional[int] = None

    def log(self, message: str) -> None:
        if self.verbose:
            print(f"[*] {message}", flush=True)

    def update_state(self, response: RadiusPacket) -> None:
        new_states = response.values(ATTR_STATE)
        if new_states:
            self.states = new_states

    def send_eap(self, eap: bytes) -> RadiusPacket:
        response = self.radius.exchange(eap, self.states)
        self.update_state(response)
        return response

    def send_tls_flight(self, request_id: int, data: bytes) -> RadiusPacket:
        if not data:
            return self.send_eap(make_eap_tls_response(request_id))

        chunks = [data[i : i + self.fragment_size] for i in range(0, len(data), self.fragment_size)]
        current_id = request_id
        total = len(data)

        for index, chunk in enumerate(chunks):
            first = index == 0
            more = index != len(chunks) - 1
            flags = 0
            if first and len(chunks) > 1:
                flags |= TLS_FLAG_LENGTH
            if more:
                flags |= TLS_FLAG_MORE
            eap = make_eap_tls_response(
                current_id,
                chunk,
                flags=flags,
                total_length=total if flags & TLS_FLAG_LENGTH else None,
            )
            response = self.send_eap(eap)

            if more:
                if response.code != ACCESS_CHALLENGE:
                    raise SolveError("server stopped during a fragmented client TLS flight")
                server_eap = parse_eap(response.eap())
                if server_eap.code != EAP_REQUEST or server_eap.eap_type != EAP_TYPE_TLS:
                    raise SolveError("expected an EAP-TLS fragment ACK")
                ack = parse_eap_tls(server_eap)
                if ack.tls_data or ack.flags & (TLS_FLAG_MORE | TLS_FLAG_START):
                    raise SolveError("server sent TLS data before all client fragments were delivered")
                current_id = server_eap.identifier
            else:
                return response

        raise AssertionError("unreachable")

    def consume_server_tls(self, eap: EapPacket) -> tuple[Optional[bytes], bool]:
        packet = parse_eap_tls(eap)
        if packet.flags & TLS_FLAG_START:
            self.server_tls_buffer.clear()
            self.server_tls_expected = None
            return b"", False

        if packet.flags & TLS_FLAG_LENGTH:
            self.server_tls_expected = packet.total_length
            self.server_tls_buffer.clear()
        self.server_tls_buffer += packet.tls_data

        if packet.flags & TLS_FLAG_MORE:
            return None, True

        complete = bytes(self.server_tls_buffer)
        expected = self.server_tls_expected
        self.server_tls_buffer.clear()
        self.server_tls_expected = None
        if expected is not None and expected != len(complete):
            raise SolveError(
                f"server EAP-TLS length mismatch: expected {expected}, got {len(complete)}"
            )
        return complete, False

    @staticmethod
    def extract_text(response: RadiusPacket) -> bytes:
        parts = response.values(ATTR_REPLY_MESSAGE)
        return b"\n".join(parts) + b"\n" + response.raw

    def handle_final(self, response: RadiusPacket) -> Optional[bytes]:
        text = self.extract_text(response)
        match = FLAG_RE.search(text)
        if match:
            return match.group(0)
        if response.code == ACCESS_REJECT:
            messages = b" | ".join(response.values(ATTR_REPLY_MESSAGE)).decode(errors="replace")
            raise SolveError(f"Access-Reject: {messages or 'no Reply-Message'}")
        if response.code == ACCESS_ACCEPT:
            readable = b" | ".join(response.values(ATTR_REPLY_MESSAGE)).decode(errors="replace")
            raise SolveError(f"Access-Accept received, but no flag was found: {readable!r}")
        return None

    def run(self) -> bytes:
        # Start with EAP-Response/Identity. FreeRADIUS will initially offer
        # its configured default (MSCHAPv2), which we NAK in favor of EAP-TLS.
        initial = make_eap(EAP_RESPONSE, 0, EAP_TYPE_IDENTITY, self.radius.identity)
        response = self.send_eap(initial)

        for step in range(512):
            flag = self.handle_final(response)
            if flag:
                return flag
            if response.code != ACCESS_CHALLENGE:
                raise SolveError(f"unexpected RADIUS code {response.code}")

            eap_raw = response.eap()
            if not eap_raw:
                raise SolveError("Access-Challenge has no EAP-Message")
            eap = parse_eap(eap_raw)

            if eap.code == EAP_SUCCESS:
                self.log("received EAP-Success before Access-Accept; acknowledging session")
                response = self.send_eap(make_eap_tls_response(eap.identifier))
                continue
            if eap.code == EAP_FAILURE:
                raise SolveError("received EAP-Failure")
            if eap.code != EAP_REQUEST:
                raise SolveError(f"unexpected EAP code {eap.code}")

            if eap.eap_type == EAP_TYPE_IDENTITY:
                self.log("server requested identity")
                response = self.send_eap(
                    make_eap(EAP_RESPONSE, eap.identifier, EAP_TYPE_IDENTITY, self.radius.identity)
                )
                continue

            if eap.eap_type != EAP_TYPE_TLS:
                self.log(f"server offered EAP type {eap.eap_type}; selecting EAP-TLS")
                response = self.send_eap(
                    make_eap(EAP_RESPONSE, eap.identifier, EAP_TYPE_NAK, bytes((EAP_TYPE_TLS,)))
                )
                continue

            tls_bytes, needs_ack = self.consume_server_tls(eap)
            if needs_ack:
                response = self.send_eap(make_eap_tls_response(eap.identifier))
                continue

            if tls_bytes:
                self.log(f"received {len(tls_bytes)} bytes of TLS data")
                self.tls.feed(tls_bytes)
            elif parse_eap_tls(eap).flags & TLS_FLAG_START:
                self.log("starting EAP-TLS handshake")

            self.tls.handshake()
            outbound = self.tls.drain()
            if outbound:
                self.log(f"sending {len(outbound)} bytes of TLS data")
                response = self.send_tls_flight(eap.identifier, outbound)
            else:
                # A completed TLS handshake still requires an empty EAP-TLS
                # response to the server's final Finished flight.
                if self.tls.complete:
                    self.log("TLS handshake complete; sending final EAP-TLS ACK")
                response = self.send_eap(make_eap_tls_response(eap.identifier))

        raise SolveError("too many EAP exchanges")


def extract_pkcs12(p12_path: Path, password: Optional[str], directory: Path) -> tuple[Path, Path]:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12
    except ImportError as exc:
        raise SolveError(
            "PKCS#12 input requires the cryptography package; install it or export PEM cert/key files"
        ) from exc

    raw = p12_path.read_bytes()
    try:
        key, cert, additional = pkcs12.load_key_and_certificates(
            raw, None if password is None else password.encode()
        )
    except Exception as exc:
        raise SolveError(f"cannot parse {p12_path}: {exc}") from exc
    if key is None or cert is None:
        raise SolveError("PKCS#12 file does not contain both certificate and private key")

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    for item in additional or []:
        # Sending a self-signed root only increases the EAP-TLS packet size.
        if item.subject == item.issuer:
            continue
        cert_pem += item.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    cert_handle = tempfile.NamedTemporaryFile(
        mode="wb", prefix=".teagod-client-", suffix=".pem", dir=directory, delete=False
    )
    key_handle = tempfile.NamedTemporaryFile(
        mode="wb", prefix=".teagod-key-", suffix=".pem", dir=directory, delete=False
    )
    cert_handle.write(cert_pem)
    key_handle.write(key_pem)
    cert_handle.close()
    key_handle.close()
    os.chmod(key_handle.name, 0o600)
    return Path(cert_handle.name), Path(key_handle.name)


def select_credentials(args: argparse.Namespace) -> tuple[Path, Path, Optional[str], list[Path]]:
    cleanup: list[Path] = []
    if args.p12:
        p12 = Path(args.p12)
        if not p12.is_file():
            raise SolveError(f"PKCS#12 file not found: {p12}")
        password = args.p12_password
        if password == "-":
            password = getpass.getpass("PKCS#12 password: ")
        cert, key = extract_pkcs12(p12, password, Path.cwd())
        cleanup += [cert, key]
        return cert, key, None, cleanup

    if args.cert and args.key:
        cert, key = Path(args.cert), Path(args.key)
        if not cert.is_file() or not key.is_file():
            raise SolveError("client certificate or private key file not found")
        key_password = args.key_password
        if key_password == "-":
            key_password = getpass.getpass("Private-key password: ")
        return cert, key, key_password, cleanup

    for name in ("client.p12", "client.pfx", "actalis.p12", "actalis.pfx"):
        path = Path(name)
        if path.is_file():
            cert, key = extract_pkcs12(path, args.p12_password, Path.cwd())
            cleanup += [cert, key]
            return cert, key, None, cleanup

    if Path("client.pem").is_file() and Path("client.key").is_file():
        return Path("client.pem"), Path("client.key"), args.key_password, cleanup

    raise SolveError(
        "no client credential found; provide an Actalis client-auth certificate with "
        "--p12 FILE or --cert FILE --key FILE"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="TEAGod Tech Staff WiFi EAP-TLS authentication solver"
    )
    parser.add_argument("host", nargs="?", default="tearoam.teagod.tech")
    parser.add_argument("port", nargs="?", type=int, default=18120)
    parser.add_argument("--secret", default="testing123", help="RADIUS shared secret")
    parser.add_argument("--identity", default="anonymous", help="outer EAP identity")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--p12", help="client PKCS#12/PFX certificate")
    group.add_argument("--cert", help="client certificate PEM, preferably with intermediates")
    parser.add_argument("--key", help="private key PEM used with --cert")
    parser.add_argument(
        "--p12-password",
        default=os.environ.get("P12_PASSWORD"),
        help="PKCS#12 password; use '-' to prompt",
    )
    parser.add_argument(
        "--key-password",
        default=os.environ.get("KEY_PASSWORD"),
        help="PEM private-key password; use '-' to prompt",
    )
    parser.add_argument(
        "--fragment-size",
        type=int,
        default=700,
        help="maximum TLS bytes per EAP fragment (default: 700)",
    )
    parser.add_argument("--framed-mtu", type=int, default=900)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("-q", "--quiet", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.fragment_size < 128 or args.fragment_size > 3000:
        raise SolveError("--fragment-size must be between 128 and 3000")
    if bool(args.cert) != bool(args.key):
        raise SolveError("--cert and --key must be supplied together")

    cert = key = None
    cleanup: list[Path] = []
    radius: Optional[RadiusClient] = None
    try:
        cert, key, key_password, cleanup = select_credentials(args)
        if not args.quiet:
            print(f"[*] client certificate: {cert}")
            print(f"[*] target: {args.host}:{args.port}/udp")
            print(f"[*] EAP-TLS fragment size: {args.fragment_size}")

        tls = TlsEngine(str(cert), str(key), key_password)
        radius = RadiusClient(
            args.host,
            args.port,
            args.secret.encode(),
            args.identity,
            args.timeout,
            args.retries,
            args.framed_mtu,
        )
        solver = EapTlsSolver(radius, tls, args.fragment_size, not args.quiet)
        flag = solver.run().decode(errors="strict")
        print(f"<FLAG>{flag}</FLAG>")
        return 0
    finally:
        if radius is not None:
            radius.close()
        for path in cleanup:
            try:
                path.unlink()
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("[-] interrupted", file=sys.stderr)
        raise SystemExit(130)
    except SolveError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        raise SystemExit(1)
