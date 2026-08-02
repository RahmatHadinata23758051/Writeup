#!/usr/bin/env python3
"""Solver for UCTF forensic challenge: Dead Reckoning.

The script parses the PCAP without third-party modules, extracts ASTERIX CAT048
radar reports from UDP/8600, finds the dominant shared motion vector, rasterizes
those synchronized tracks, and decodes the resulting 7-row dot-matrix text.
"""

from __future__ import annotations

import argparse
import collections
import math
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Sequence, Tuple


@dataclass(frozen=True)
class RadarReport:
    tod: float
    track_no: int
    x_raw: int
    y_raw: int


PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


def iter_pcap_packets(path: Path) -> Iterator[bytes]:
    with path.open("rb") as handle:
        global_header = handle.read(24)
        if len(global_header) != 24:
            raise ValueError("PCAP global header is incomplete")

        try:
            endian, _timestamp_scale = PCAP_MAGIC[global_header[:4]]
        except KeyError as exc:
            raise ValueError(f"Unsupported PCAP magic: {global_header[:4].hex()}") from exc

        link_type = struct.unpack(endian + "I", global_header[20:24])[0]
        if link_type != 1:
            raise ValueError(f"Only Ethernet PCAP is supported, link type={link_type}")

        packet_header = struct.Struct(endian + "IIII")
        while True:
            raw_header = handle.read(packet_header.size)
            if not raw_header:
                break
            if len(raw_header) != packet_header.size:
                raise ValueError("Truncated PCAP packet header")

            _ts_sec, _ts_frac, captured_len, _original_len = packet_header.unpack(raw_header)
            frame = handle.read(captured_len)
            if len(frame) != captured_len:
                raise ValueError("Truncated PCAP packet data")
            yield frame


def extract_udp_payload(frame: bytes) -> Tuple[int, int, bytes] | None:
    if len(frame) < 14:
        return None

    ether_type = struct.unpack("!H", frame[12:14])[0]
    offset = 14

    if ether_type == 0x8100:  # 802.1Q VLAN
        if len(frame) < 18:
            return None
        ether_type = struct.unpack("!H", frame[16:18])[0]
        offset = 18

    if ether_type != 0x0800 or len(frame) < offset + 20:
        return None

    version_ihl = frame[offset]
    if version_ihl >> 4 != 4:
        return None

    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(frame) < offset + ihl + 8:
        return None

    if frame[offset + 9] != 17:  # UDP
        return None

    udp_offset = offset + ihl
    src_port, dst_port, udp_len, _checksum = struct.unpack(
        "!HHHH", frame[udp_offset : udp_offset + 8]
    )
    if udp_len < 8:
        return None

    payload_end = min(len(frame), udp_offset + udp_len)
    return src_port, dst_port, frame[udp_offset + 8 : payload_end]


def parse_cat048(payload: bytes) -> RadarReport | None:
    """Parse the fixed CAT048 layout used by the challenge.

    Layout after the three-byte ASTERIX header:
      FSPEC fd 18
      I048/010 Data Source Identifier       2 bytes
      I048/140 Time of Day                  3 bytes
      I048/020 Target Report Descriptor     1 byte
      I048/040 Measured Polar Position      4 bytes
      I048/070 Mode-3/A Code                2 bytes
      I048/090 Flight Level                 2 bytes
      I048/161 Track Number                 2 bytes
      I048/042 Cartesian Position X/Y       4 bytes
    """

    if len(payload) != 25:
        return None
    if payload[0] != 0x30:  # Category 48
        return None
    if int.from_bytes(payload[1:3], "big") != len(payload):
        return None
    if payload[3:5] != b"\xfd\x18":
        return None

    tod = int.from_bytes(payload[7:10], "big") / 128.0
    track_no = int.from_bytes(payload[19:21], "big") & 0x0FFF
    x_raw = int.from_bytes(payload[21:23], "big", signed=True)
    y_raw = int.from_bytes(payload[23:25], "big", signed=True)
    return RadarReport(tod=tod, track_no=track_no, x_raw=x_raw, y_raw=y_raw)


def extract_reports(path: Path) -> Dict[int, List[RadarReport]]:
    tracks: Dict[int, List[RadarReport]] = collections.defaultdict(list)

    for frame in iter_pcap_packets(path):
        udp = extract_udp_payload(frame)
        if udp is None:
            continue

        src_port, dst_port, payload = udp
        if src_port != 59999 or dst_port != 8600:
            continue

        report = parse_cat048(payload)
        if report is not None:
            tracks[report.track_no].append(report)

    for reports in tracks.values():
        reports.sort(key=lambda item: item.tod)
    return dict(tracks)


def motion_key(reports: Sequence[RadarReport]) -> Tuple[float, float]:
    """Return motion per report interval in nautical miles, rounded for clustering."""

    first, _middle, last = reports
    vx = (last.x_raw - first.x_raw) / (2.0 * 128.0)
    vy = (last.y_raw - first.y_raw) / (2.0 * 128.0)
    return round(vx, 2), round(vy, 2)


def select_synchronized_tracks(
    tracks: Dict[int, List[RadarReport]],
) -> Tuple[Tuple[float, float], List[Tuple[int, RadarReport]]]:
    motions: collections.Counter[Tuple[float, float]] = collections.Counter()

    for reports in tracks.values():
        if len(reports) == 3:
            motions[motion_key(reports)] += 1

    if not motions:
        raise ValueError("No three-report radar tracks were found")

    dominant_motion, _count = motions.most_common(1)[0]
    selected: List[Tuple[int, RadarReport]] = []

    for track_no, reports in tracks.items():
        if len(reports) == 3 and motion_key(reports) == dominant_motion:
            selected.append((track_no, reports[1]))

    selected.sort(key=lambda item: item[0])
    return dominant_motion, selected


def grid_step(values: Iterable[int]) -> int:
    unique = sorted(set(values))
    differences = [b - a for a, b in zip(unique, unique[1:]) if b != a]
    if not differences:
        raise ValueError("Cannot determine grid step from one coordinate")

    step = differences[0]
    for difference in differences[1:]:
        step = math.gcd(step, difference)
    if step <= 0:
        raise ValueError("Invalid grid step")
    return step


def rasterize(points: Sequence[RadarReport]) -> List[str]:
    x_values = [point.x_raw for point in points]
    y_values = [point.y_raw for point in points]
    step = math.gcd(grid_step(x_values), grid_step(y_values))

    x_min, x_max = min(x_values), max(x_values)
    y_min, y_max = min(y_values), max(y_values)
    width = (x_max - x_min) // step + 1
    height = (y_max - y_min) // step + 1

    canvas = [[" " for _ in range(width)] for _ in range(height)]
    for point in points:
        column = (point.x_raw - x_min) // step
        row = (y_max - point.y_raw) // step
        canvas[row][column] = "#"

    return ["".join(row) for row in canvas]


def split_glyphs(raster: Sequence[str]) -> List[Tuple[str, ...]]:
    height = len(raster)
    width = len(raster[0])
    blank = [all(raster[row][column] == " " for row in range(height)) for column in range(width)]

    glyphs: List[Tuple[str, ...]] = []
    column = 0
    while column < width:
        while column < width and blank[column]:
            column += 1
        if column >= width:
            break

        start = column
        while column < width and not blank[column]:
            column += 1
        glyphs.append(tuple(raster[row][start:column] for row in range(height)))

    return glyphs


def pattern(*rows: str) -> Tuple[str, ...]:
    return tuple(row.replace(".", " ") for row in rows)


FONT = {
    pattern(".....", ".....", "#...#", "#...#", "#...#", "#..##", ".##.#"): "u",
    pattern(".....", ".....", ".###.", "#...#", "#....", "#...#", ".###."): "c",
    pattern(".#...", ".#...", "###..", ".#...", ".#...", ".#..#", "..##."): "t",
    pattern("..##.", ".#..#", ".#...", "###..", ".#...", ".#...", ".#..."): "f",
    pattern(".##", ".#.", ".#.", "#..", ".#.", ".#.", ".##"): "{",
    pattern("...#.", "..##.", ".#.#.", "#..#.", "#####", "...#.", "...#."): "4",
    pattern(".....", ".....", "#.##.", "##..#", "#....", "#....", "#...."): "r",
    pattern(".....", ".....", ".####", "#...#", ".####", "....#", ".###."): "g",
    pattern("#####", "...#.", "..#..", "..##.", "....#", "#...#", ".###."): "3",
    pattern(".....", ".....", ".....", ".....", ".....", ".....", "#####"): "_",
    pattern("#....", "#....", "#.##.", "##..#", "#...#", "#...#", "#...#"): "h",
    pattern(".....", ".....", ".####", "#....", ".###.", "....#", "####."): "s",
    pattern("#....", "#....", "#.##.", "##..#", "#...#", "#...#", "####."): "b",
    pattern(".....", ".....", "#.##.", "##..#", "#...#", "#...#", "#...#"): "n",
    pattern("#...", "#...", "#..#", "#.#.", "##..", "#.#.", "#..#"): "k",
    pattern("....#", "....#", ".##.#", "#..##", "#...#", "#...#", ".####"): "d",
    pattern(".###.", "#...#", "#..##", "#.#.#", "##..#", "#...#", ".###."): "0",
    pattern(".....", ".....", "#...#", "#...#", "#.#.#", "#.#.#", ".#.#."): "w",
    pattern("##.", ".#.", ".#.", "..#", ".#.", ".#.", "##."): "}",
}


def decode_raster(raster: Sequence[str]) -> str:
    glyphs = split_glyphs(raster)
    decoded = []
    for index, glyph in enumerate(glyphs):
        character = FONT.get(glyph)
        if character is None:
            printable = "\n".join(row.replace(" ", ".") for row in glyph)
            raise ValueError(f"Unknown glyph #{index}:\n{printable}")
        decoded.append(character)
    return "".join(decoded)


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve UCTF Dead Reckoning")
    parser.add_argument("pcap", nargs="?", default="chall.pcap", type=Path)
    parser.add_argument("--show-raster", action="store_true")
    args = parser.parse_args()

    if not args.pcap.is_file():
        print(f"error: file not found: {args.pcap}", file=sys.stderr)
        return 1

    tracks = extract_reports(args.pcap)
    dominant_motion, selected = select_synchronized_tracks(tracks)
    raster = rasterize([middle for _track_no, middle in selected])
    flag = decode_raster(raster)

    print(f"CAT048 tracks      : {len(tracks)}")
    print(f"Dominant motion    : vx={dominant_motion[0]:.2f}, vy={dominant_motion[1]:.2f}")
    print(f"Synchronized tracks: {len(selected)}")
    if args.show_raster:
        print()
        for row in raster:
            print(row.rstrip())
        print()
    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
