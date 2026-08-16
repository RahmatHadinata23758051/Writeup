#!/usr/bin/env python3
"""Recover the XOR evidence from Two Sides of Midnight."""

from collections import defaultdict
from pathlib import Path
import io
import subprocess
import zipfile


PCAP = Path(__file__).with_name("two-side-of-midnight.pcapng")


def payloads_by_side():
    fields = [
        "frame.interface_id", "tcp.stream", "tcp.seq", "tcp.len", "tcp.payload"
    ]
    cmd = ["tshark", "-r", str(PCAP), "-T", "fields", "-E", "separator=|"]
    for field in fields:
        cmd += ["-e", field]
    rows = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    # Keep one payload per sequence range. Exact retransmission duplicates are ignored.
    sides = defaultdict(dict)
    for row in rows.splitlines():
        parts = row.split("|")
        if len(parts) != 5 or not parts[4] or parts[3] == "0":
            continue
        iface, stream, seq, length, payload = parts
        key = (int(iface), int(stream), int(seq), int(length))
        sides[(int(iface), int(stream))][key[2:]] = bytes.fromhex(payload)
    return sides


def main():
    sides = payloads_by_side()
    # Only stream 0 differs between tap-ingress (0) and tap-egress (1).
    ingress = b"".join(sides[(0, 0)][k] for k in sorted(sides[(0, 0)]))
    egress = b"".join(sides[(1, 0)][k] for k in sorted(sides[(1, 0)]))
    if len(ingress) != len(egress):
        raise RuntimeError("sequence-space lengths differ")

    evidence = bytes(a ^ b for a, b in zip(ingress, egress))
    zip_offset = evidence.find(b"PK\x03\x04")
    if zip_offset < 0:
        raise RuntimeError("recovered evidence is not a ZIP archive")

    with zipfile.ZipFile(io.BytesIO(evidence[zip_offset:])) as archive:
        out_dir = PCAP.parent / "recovered"
        out_dir.mkdir(exist_ok=True)
        archive.extractall(out_dir)
        text = (out_dir / "incident.txt").read_text()
        print(text, end="")


if __name__ == "__main__":
    main()
