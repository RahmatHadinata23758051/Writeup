#!/usr/bin/env python3
from pathlib import Path
import re

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz., "


def extract_constants(source: str):
    nums = [int(x) for x in re.findall(r"\d{100,}", source)]
    if len(nums) < 2:
        raise ValueError("could not find Babel constants")
    return nums[0], nums[1]


def page_seed_from_text(text: str, page_constant: int) -> int:
    n = 0
    for i, ch in enumerate(text):
        if ch not in ALPHABET:
            raise ValueError(f"character not in alphabet: {ch!r}")
        n += ALPHABET.index(ch) * (55 ** i)
    return n - page_constant


def image_pixels_from_seed(seed: int, image_constant: int):
    n = seed - image_constant
    pixels = []
    for _ in range(225):
        n, r = divmod(n, 256)
        n, g = divmod(n, 256)
        n, b = divmod(n, 256)
        pixels.append((r, g, b))
    if n != 0:
        raise ValueError("image seed did not fully decode")
    return pixels


def decode_flag(author: str, pixels):
    # The generated image is intentionally almost black. Its raw RGB triples are
    # decimal indexes into the author text. Values may wrap modulo len(author).
    chars = []
    for r, g, b in pixels:
        if (r, g, b) == (0, 0, 0):
            break
        idx = int(f"{r}{g}{b}") % len(author)
        chars.append(author[idx])

    compact = "".join(chars)
    if "CTF" not in compact:
        return compact

    prefix_end = compact.index("CTF") + 3
    return compact[:prefix_end] + "{" + compact[prefix_end:] + "}"


def main():
    base = Path(__file__).resolve().parent
    author = (base / "author.txt").read_text().rstrip("\n")
    source = (base / "babel.py").read_text()

    page_constant, image_constant = extract_constants(source)
    seed = page_seed_from_text(author, page_constant)
    pixels = image_pixels_from_seed(seed, image_constant)
    flag = decode_flag(author, pixels)

    print(f"seed = {seed}")
    print(f"flag = {flag}")
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
