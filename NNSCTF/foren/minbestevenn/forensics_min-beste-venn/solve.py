#!/usr/bin/env python3
import subprocess
import sys


PCAP = "capture.pcap"


def tshark_requests(pcap_path: str):
    out = subprocess.check_output(
        [
            "tshark",
            "-r",
            pcap_path,
            "-Y",
            "http.request",
            "-T",
            "fields",
            "-e",
            "frame.time_relative",
            "-e",
            "http.request.uri",
        ],
        text=True,
    )
    for line in out.splitlines():
        if not line.strip():
            continue
        ts, uri = line.split("\t", 1)
        yield float(ts), uri


def extract_flag(pcap_path: str) -> str:
    markers = []
    data = []

    for ts, uri in tshark_requests(pcap_path):
        parts = uri.strip("/").split("/")
        if len(parts) >= 3 and parts[1] == "c" and parts[2].startswith("s"):
            markers.append((ts, parts[2]))
            continue

        if len(parts) == 5 and parts[1] == "d" and parts[2] == "c" and parts[3] == "1":
            value = int(parts[4].removesuffix(".css"))
            data.append((ts, value))

    merged = {}
    for idx, (start, _) in enumerate(markers):
        end = markers[idx + 1][0] if idx + 1 < len(markers) else float("inf")
        chunk = [value for ts, value in data if start < ts < end]

        if not chunk or len(chunk) == 440:
            continue

        points = {(value // 10, value % 10) for value in chunk}
        width = max(x for x, _ in points) + 1
        for x in range(width):
            byte = 0
            for y in range(8):
                if (x, y) in points:
                    byte |= 1 << (7 - y)
            merged[x] = merged.get(x, 0) | byte

    payload = bytes(merged[x] for x in range(max(merged) + 1))
    length = payload[0]
    body = payload[1 : 1 + length].decode()
    return body


def main():
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else PCAP
    print(extract_flag(pcap_path))


if __name__ == "__main__":
    main()
