#!/usr/bin/env python3
import base64
import subprocess

PCAP = "suspect.pcapng"
KNOWN_PREFIX = b"uni6CTF{"  # known flag format


def run(cmd):
    return subprocess.check_output(cmd, text=True).strip().splitlines()


def get_evil_queries(pcap):
    lines = run([
        "tshark", "-r", pcap,
        "-Y", "dns.qry.name contains evil.com",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "dns.qry.name",
    ])
    pairs = []
    for line in lines:
        if not line.strip():
            continue
        t, q = line.split("\t", 1)
        pairs.append((float(t), q.strip()))
    pairs.sort(key=lambda x: x[0])
    return [q for _, q in pairs]


def reconstruct_b64(queries):
    chunks = []
    for q in queries:
        labels = q.split(".")
        data_labels = labels[:-2]  # remove evil.com
        chunks.append("".join(data_labels))
    return "".join(chunks)


def xor_repeat(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def main():
    queries = get_evil_queries(PCAP)
    b64_text = reconstruct_b64(queries)
    ciphertext = base64.b64decode(b64_text)

    # Derive repeating key from known prefix at offset 0.
    key = bytes(ciphertext[i] ^ KNOWN_PREFIX[i] for i in range(4))  # b"uni6"
    plaintext = xor_repeat(ciphertext, key)
    print(plaintext.decode())


if __name__ == "__main__":
    main()
