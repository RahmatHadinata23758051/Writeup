#!/usr/bin/env python3
import json
import re
import statistics
from collections import defaultdict
from pathlib import Path

BLOCK_SIZE = 16
FLAG_RE = re.compile(rb"grodno\{[^}\r\n]+\}")


def load_packet(path: str = "packet.hex") -> bytes:
    raw = "".join(Path(path).read_text(encoding="utf-8").split())
    packet = bytes.fromhex(raw)

    if len(packet) % BLOCK_SIZE != 0:
        raise ValueError("Packet length is not aligned to AES block size")

    if len(packet) < BLOCK_SIZE * 2:
        raise ValueError("Packet must contain an IV and at least one ciphertext block")

    return packet


def load_trace(path: str = "timing_trace.json") -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))

    if not isinstance(data, list):
        raise TypeError("Timing trace must be a JSON array")

    return data


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data:
        raise ValueError("Cannot unpad empty plaintext")

    padding = data[-1]

    if padding < 1 or padding > block_size:
        raise ValueError("Invalid PKCS#7 padding length")

    if data[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid PKCS#7 padding bytes")

    return data[:-padding]


def recover_plaintext(packet: bytes, trace: list[dict]) -> tuple[bytes, list[dict]]:
    blocks = [
        packet[offset:offset + BLOCK_SIZE]
        for offset in range(0, len(packet), BLOCK_SIZE)
    ]

    # blocks[0] is the IV. Trace block numbers target blocks[1:].
    target_count = len(blocks) - 1

    timings: dict[tuple[int, int, int], list[int]] = defaultdict(list)

    for row in trace:
        block = int(row["block"])
        pad = int(row["pad"])
        guess = int(row["guess"])
        elapsed = int(row["elapsed_ns"])

        if not 1 <= block <= target_count:
            raise ValueError(f"Invalid block number: {block}")
        if not 1 <= pad <= BLOCK_SIZE:
            raise ValueError(f"Invalid padding value: {pad}")
        if not 0 <= guess <= 255:
            raise ValueError(f"Invalid byte guess: {guess}")

        timings[(block, pad, guess)].append(elapsed)

    plaintext_blocks = []
    winners = []

    for block_number in range(1, target_count + 1):
        previous = blocks[block_number - 1]
        intermediate = bytearray(BLOCK_SIZE)

        for pad in range(1, BLOCK_SIZE + 1):
            position = BLOCK_SIZE - pad
            candidates = []

            for guess in range(256):
                samples = timings.get((block_number, pad, guess))

                if not samples:
                    raise RuntimeError(
                        f"Missing timing samples for block={block_number}, "
                        f"pad={pad}, guess={guess}"
                    )

                score = statistics.median(samples)
                candidates.append((score, guess, samples))

            candidates.sort(reverse=True)
            best_score, best_guess, best_samples = candidates[0]
            second_score = candidates[1][0]

            # The trace records the forged previous-block byte. A valid
            # PKCS#7 byte satisfies:
            #
            #     forged_byte XOR intermediate_byte = pad
            #
            # Therefore:
            #
            #     intermediate_byte = forged_byte XOR pad
            intermediate[position] = best_guess ^ pad

            winners.append({
                "block": block_number,
                "pad": pad,
                "position": position,
                "guess": best_guess,
                "median_ns": int(best_score),
                "runner_up_ns": int(second_score),
                "samples": best_samples,
            })

        plaintext_blocks.append(
            bytes(
                intermediate[index] ^ previous[index]
                for index in range(BLOCK_SIZE)
            )
        )

    return b"".join(plaintext_blocks), winners


def main() -> None:
    metadata = json.loads(
        Path("metadata.json").read_text(encoding="utf-8")
    )

    if metadata.get("mode") != "aes-cbc":
        raise RuntimeError(
            f"Expected aes-cbc, got {metadata.get('mode')!r}"
        )

    packet = load_packet()
    trace = load_trace()

    padded_plaintext, winners = recover_plaintext(packet, trace)
    plaintext = pkcs7_unpad(padded_plaintext)

    print(f"[+] Packet blocks : {len(packet) // BLOCK_SIZE}")
    print(f"[+] Trace rows    : {len(trace)}")
    print("[+] Timing winners:")
    for row in winners:
        print(
            f"    block={row['block']} pad={row['pad']:2d} "
            f"guess=0x{row['guess']:02x} "
            f"median={row['median_ns']} ns "
            f"runner-up={row['runner_up_ns']} ns"
        )

    print("\n[+] Recovered plaintext:")
    print(plaintext.decode("utf-8"))

    match = FLAG_RE.search(plaintext)
    if not match:
        raise RuntimeError("No valid grodno{} flag found")

    flag = match.group().decode("ascii")
    print(f"\n<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
