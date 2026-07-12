#!/usr/bin/env python3
"""Solver for Grodno CTF 2026 Misc - Fear And Horror.

The covert channel is stored in classic-PCAP packet record lengths:
    symbol = original_wire_length - captured_length

Each symbol is in the range 0..7, so it carries three bits.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

TARGET_IP_DEFAULT = "193.109.69.2"
EXPECTED_FRAME_LENGTHS = (237, 1356, 147, 296, 271, 225)
FLAG_RE = re.compile(rb"grodno\{[^}\r\n]+\}")


@dataclass(frozen=True)
class PacketRecord:
    index: int
    timestamp: float
    captured_length: int
    original_length: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    tcp_payload_length: int

    @property
    def client_port(self) -> int:
        return self.src_port if self.dst_port == 443 else self.dst_port

    @property
    def delta(self) -> int:
        return self.original_length - self.captured_length


def pcap_format(magic: bytes) -> tuple[str, float]:
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
    }
    try:
        return formats[magic]
    except KeyError as exc:
        raise ValueError("File bukan classic PCAP yang didukung") from exc


def parse_ipv4_tcp(frame: bytes) -> tuple[str, str, int, int, int] | None:
    if len(frame) < 14:
        return None

    offset = 14
    ether_type = struct.unpack("!H", frame[12:14])[0]

    # Handle one or more VLAN tags.
    while ether_type in (0x8100, 0x88A8):
        if len(frame) < offset + 4:
            return None
        ether_type = struct.unpack("!H", frame[offset + 2 : offset + 4])[0]
        offset += 4

    if ether_type != 0x0800 or len(frame) < offset + 20:
        return None

    version_ihl = frame[offset]
    if version_ihl >> 4 != 4:
        return None

    ip_header_length = (version_ihl & 0x0F) * 4
    if ip_header_length < 20 or len(frame) < offset + ip_header_length:
        return None

    protocol = frame[offset + 9]
    if protocol != 6:
        return None

    src_ip = str(ipaddress.ip_address(frame[offset + 12 : offset + 16]))
    dst_ip = str(ipaddress.ip_address(frame[offset + 16 : offset + 20]))

    tcp_offset = offset + ip_header_length
    if len(frame) < tcp_offset + 20:
        return None

    src_port, dst_port = struct.unpack("!HH", frame[tcp_offset : tcp_offset + 4])
    tcp_header_length = (frame[tcp_offset + 12] >> 4) * 4
    if tcp_header_length < 20 or len(frame) < tcp_offset + tcp_header_length:
        return None

    payload_length = max(0, len(frame) - (tcp_offset + tcp_header_length))
    return src_ip, dst_ip, src_port, dst_port, payload_length


def read_pcap(path: Path) -> list[PacketRecord]:
    records: list[PacketRecord] = []

    with path.open("rb") as handle:
        global_header = handle.read(24)
        if len(global_header) != 24:
            raise ValueError("Header PCAP tidak lengkap")

        endian, timestamp_divisor = pcap_format(global_header[:4])
        index = 0

        while True:
            packet_header = handle.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise ValueError("Record header PCAP terpotong")

            seconds, fraction, captured_length, original_length = struct.unpack(
                endian + "IIII", packet_header
            )
            frame = handle.read(captured_length)
            if len(frame) != captured_length:
                raise ValueError("Data frame PCAP terpotong")

            index += 1
            parsed = parse_ipv4_tcp(frame)
            if parsed is None:
                continue

            src_ip, dst_ip, src_port, dst_port, payload_length = parsed
            records.append(
                PacketRecord(
                    index=index,
                    timestamp=seconds + fraction / timestamp_divisor,
                    captured_length=captured_length,
                    original_length=original_length,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    tcp_payload_length=payload_length,
                )
            )

    return records


def extract_matrix(records: list[PacketRecord], target_ip: str) -> list[tuple[int, list[int]]]:
    stage_by_length = {length: stage for stage, length in enumerate(EXPECTED_FRAME_LENGTHS)}
    flows: dict[int, dict[int, PacketRecord]] = {}
    first_seen: dict[int, float] = {}

    for record in records:
        if target_ip not in (record.src_ip, record.dst_ip):
            continue
        if 443 not in (record.src_port, record.dst_port):
            continue
        if record.tcp_payload_length == 0:
            continue

        stage = stage_by_length.get(record.original_length)
        if stage is None:
            continue

        # The covert symbol must fit in three bits.
        if not 0 <= record.delta <= 7:
            continue

        port = record.client_port
        flows.setdefault(port, {}).setdefault(stage, record)
        first_seen[port] = min(first_seen.get(port, record.timestamp), record.timestamp)

    complete: list[tuple[float, int, list[int]]] = []
    for port, stages in flows.items():
        if len(stages) != len(EXPECTED_FRAME_LENGTHS):
            continue
        row = [stages[i].delta for i in range(len(EXPECTED_FRAME_LENGTHS))]
        complete.append((first_seen[port], port, row))

    complete.sort()
    return [(port, row) for _, port, row in complete]


def decode(rows: list[tuple[int, list[int]]]) -> tuple[bytes, int]:
    if len(rows) != 9:
        raise ValueError(f"Harus menemukan 9 sesi lengkap, ditemukan {len(rows)}")

    sync_rows = [(port, row) for port, row in rows if all(value == 0 for value in row)]
    if len(sync_rows) != 1:
        raise ValueError("Baris sinkronisasi nol tidak unik")

    sync_port = sync_rows[0][0]
    data_rows = [row for _, row in rows if any(row)]
    if len(data_rows) != 8:
        raise ValueError("Setelah sinkronisasi dibuang harus tersisa 8 baris data")

    # Read column by column. Eight rows per column produce 8 * 3 = 24 bits.
    symbols = [data_rows[row][column] for column in range(6) for row in range(8)]
    bitstream = "".join(f"{symbol:03b}" for symbol in symbols)

    if len(bitstream) % 8 != 0:
        raise ValueError("Panjang bitstream bukan kelipatan delapan")

    decoded = bytes(
        int(bitstream[offset : offset + 8], 2)
        for offset in range(0, len(bitstream), 8)
    )
    return decoded, sync_port


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", nargs="?", default="chal_steg.pcap", type=Path)
    parser.add_argument("--target-ip", default=TARGET_IP_DEFAULT)
    args = parser.parse_args()

    try:
        records = read_pcap(args.pcap)
        rows = extract_matrix(records, args.target_ip)
        decoded, sync_port = decode(rows)
    except (OSError, ValueError) as exc:
        print(f"[-] gagal: {exc}", file=sys.stderr)
        return 1

    print(f"[+] target C2: {args.target_ip}:443")
    print("[+] delta matrix (orig_len - incl_len):")
    for port, row in rows:
        print(f"    {port}: {' '.join(map(str, row))}")
    print(f"[+] sync row dibuang: client port {sync_port}")
    print(f"[+] decoded hex: {decoded.hex()}")

    match = FLAG_RE.fullmatch(decoded)
    if match is None:
        print(f"[-] hasil decode bukan flag valid: {decoded!r}", file=sys.stderr)
        return 1

    flag = match.group().decode("ascii")
    print(f"<FLAG>{flag}</FLAG>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
