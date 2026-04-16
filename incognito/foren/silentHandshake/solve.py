#!/usr/bin/env python3
import argparse
import subprocess
import sys

SRC_IP = "10.0.5.23"
DST_IP = "198.51.100.45"
MULTIPLIER = 80211
MASK_24 = 0x00FFFFFF
TARGET_WINDOW = 64240


def extract_seq_raw(pcap_path: str):
    display_filter = (
        f"ip.src=={SRC_IP} && ip.dst=={DST_IP} && "
        f"tcp.flags.syn==1 && tcp.flags.ack==0 && "
        f"tcp.window_size_value=={TARGET_WINDOW}"
    )
    cmd = [
        "tshark",
        "-n",
        "-r",
        pcap_path,
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-e",
        "tcp.seq_raw",
    ]

    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print("Error: tshark not found in PATH", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError:
        print("Error: failed to parse pcap with tshark", file=sys.stderr)
        sys.exit(1)

    seqs = [int(line.strip()) for line in out.splitlines() if line.strip()]
    return seqs


def recover_flag(seqs):
    if not seqs:
        raise ValueError("No matching packets found.")

    inv = pow(MULTIPLIER, -1, 1 << 24)
    chars = []

    for s in seqs:
        low24 = s & MASK_24
        plain_val = (low24 * inv) & MASK_24
        chars.append(plain_val & 0xFF)

    text = bytes(chars).decode("ascii", errors="replace")
    return text


def main():
    parser = argparse.ArgumentParser(description="Solve The Silent Handshake forensic challenge")
    parser.add_argument("pcap", nargs="?", default="packet_capture.pcap", help="Path to pcap/pcapng")
    args = parser.parse_args()

    seqs = extract_seq_raw(args.pcap)
    flag = recover_flag(seqs)

    print(flag)


if __name__ == "__main__":
    main()
