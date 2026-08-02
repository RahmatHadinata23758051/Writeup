#!/usr/bin/env python3
"""Decoder for UCTF 2026 - Carrier Lock."""

from pathlib import Path
import re

ASM = bytes.fromhex("1ACFFC1D")
TRANSFER_FRAME_SIZE = 1024
TM_PRIMARY_HEADER_SIZE = 6
MESSAGE_APID = 250
IDLE_APID = 0x7FF


def ccsds_pn_sequence(length: int) -> bytes:
    """Generate the CCSDS TM randomizer sequence.

    Polynomial: x^8 + x^7 + x^5 + x^3 + 1
    Initial state: all ones
    """
    state = 0xFF
    output_bits: list[int] = []

    for _ in range(length * 8):
        output_bits.append(state & 1)
        feedback = (
            ((state >> 7) & 1)
            ^ ((state >> 5) & 1)
            ^ ((state >> 3) & 1)
            ^ (state & 1)
        )
        state = (state >> 1) | (feedback << 7)

    output = bytearray()
    for offset in range(0, len(output_bits), 8):
        value = 0
        for bit in output_bits[offset : offset + 8]:
            value = (value << 1) | bit
        output.append(value)

    return bytes(output)


def split_cadu_frames(raw: bytes) -> list[bytes]:
    """Locate consecutive ASM markers and return 1024-byte transfer frames."""
    positions: list[int] = []
    cursor = 0

    while True:
        position = raw.find(ASM, cursor)
        if position < 0:
            break
        positions.append(position)
        cursor = position + 1

    if not positions:
        raise ValueError("CCSDS ASM 1ACFFC1D was not found")

    expected_spacing = len(ASM) + TRANSFER_FRAME_SIZE
    for previous, current in zip(positions, positions[1:]):
        if current - previous != expected_spacing:
            raise ValueError(
                f"Unexpected frame spacing: {current - previous}, "
                f"expected {expected_spacing}"
            )

    frames: list[bytes] = []
    for position in positions:
        start = position + len(ASM)
        end = start + TRANSFER_FRAME_SIZE
        frame = raw[start:end]
        if len(frame) != TRANSFER_FRAME_SIZE:
            raise ValueError("Truncated transfer frame")
        frames.append(frame)

    return frames


def derandomize_frames(frames: list[bytes]) -> list[bytes]:
    pn = ccsds_pn_sequence(TRANSFER_FRAME_SIZE)
    return [bytes(value ^ mask for value, mask in zip(frame, pn)) for frame in frames]


def build_packet_stream(frames: list[bytes]) -> bytes:
    """Remove each six-byte TM primary header and join the continuous data field."""
    stream = bytearray()

    for expected_count, frame in enumerate(frames):
        if frame[:2] != bytes.fromhex("0AB0"):
            raise ValueError(f"Unexpected TM frame identifier in frame {expected_count}")

        master_count = frame[2]
        virtual_count = frame[3]
        if master_count != expected_count or virtual_count != expected_count:
            raise ValueError(
                f"Unexpected frame count at frame {expected_count}: "
                f"MC={master_count}, VC={virtual_count}"
            )

        stream.extend(frame[TM_PRIMARY_HEADER_SIZE:])

    return bytes(stream)


def extract_message_chunks(packet_stream: bytes) -> list[tuple[int, bytes]]:
    chunks: list[tuple[int, bytes]] = []
    offset = 0

    while offset + 6 <= len(packet_stream):
        header = packet_stream[offset : offset + 6]
        version = header[0] >> 5
        apid = ((header[0] & 0x07) << 8) | header[1]
        sequence_count = ((header[2] & 0x3F) << 8) | header[3]
        data_length = int.from_bytes(header[4:6], "big") + 1
        packet_end = offset + 6 + data_length

        if version != 0:
            raise ValueError(f"Invalid CCSDS packet version at offset {offset}")
        if packet_end > len(packet_stream):
            raise ValueError("Truncated CCSDS space packet")

        payload = packet_stream[offset + 6 : packet_end]

        if apid == MESSAGE_APID:
            chunks.append((sequence_count, payload))
        elif apid == IDLE_APID:
            break

        offset = packet_end

    return chunks


def main() -> None:
    path = Path(__file__).with_name("downlink.bin")
    raw = path.read_bytes()

    cadu_frames = split_cadu_frames(raw)
    transfer_frames = derandomize_frames(cadu_frames)
    packet_stream = build_packet_stream(transfer_frames)
    chunks = extract_message_chunks(packet_stream)

    if not chunks:
        raise ValueError(f"No packets found for APID {MESSAGE_APID}")

    chunks.sort(key=lambda item: item[0])
    sequence_counts = [sequence for sequence, _ in chunks]
    if sequence_counts != list(range(len(chunks))):
        raise ValueError(f"Non-contiguous message sequence: {sequence_counts}")

    flag = b"".join(payload for _, payload in chunks).decode("ascii")
    if re.fullmatch(r"uctf\{[ -~]+\}", flag) is None:
        raise ValueError(f"Decoded text is not a valid UCTF flag: {flag!r}")

    print(f"frames: {len(cadu_frames)}")
    print(f"message packets: {len(chunks)}")
    for sequence, payload in chunks:
        print(f"seq {sequence}: {payload.decode('ascii')}")
    print(flag)


if __name__ == "__main__":
    main()
