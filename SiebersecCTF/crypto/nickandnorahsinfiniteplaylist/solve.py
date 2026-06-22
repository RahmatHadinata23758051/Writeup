#!/usr/bin/env python3
import glob
import re
import sys
from pathlib import Path


def bxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def load_output(path: str | None = None) -> tuple[bytes, bytes, Path]:
    candidates = []
    if path:
        candidates.append(Path(path))
    candidates += [Path("output.txt"), Path("output(2).txt")]
    candidates += [Path(p) for p in sorted(glob.glob("output*.txt"))]

    seen = set()
    for p in candidates:
        if p in seen:
            continue
        seen.add(p)
        if not p.exists():
            continue
        data = p.read_text(errors="ignore")
        hits = re.findall(r"c[12]:\s*([0-9a-fA-F]+)", data)
        if len(hits) >= 2:
            return bytes.fromhex(hits[0]), bytes.fromhex(hits[1]), p

    raise SystemExit("could not find output file containing c1/c2")


def main() -> None:
    c1, c2, path = load_output(sys.argv[1] if len(sys.argv) > 1 else None)

    # AES-CTR was initialized with the same key+nonce for both messages.
    # That reuses the exact same keystream, so c1 ^ c2 = p1 ^ p2.
    x = bxor(c1, c2)

    # Crib-dragged Nick message. The first bytes confirm the speakers:
    #   x ^ b"nick: " -> b"norah:"
    # Continuing the English crib reveals Norah's whole overlapping message.
    nick_crib = (
        b"nick: yo norah, been listening to 'pink moon' by nick drake "
        b"nonstop. birds is incr"
    )

    norah = bxor(x, nick_crib)
    m = re.search(rb"sctf\{[^}]+\}", norah)
    if not m:
        raise SystemExit("flag not recovered; crib did not expose an sctf{...} token")

    flag = m.group(0).decode()
    print(f"[+] parsed ciphertexts from {path}")
    print(f"[+] c1 length: {len(c1)} bytes")
    print(f"[+] c2 length: {len(c2)} bytes")
    print("[+] recovered Norah plaintext overlap:")
    print(norah.decode())
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
