#!/usr/bin/env python3
from pathlib import Path
import base64

EMOJI_FILE = Path("emoji.txt")

BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

CODON_TABLE = {
    "TTT": "F", "TTC": "F", "TTA": "L", "TTG": "L",
    "TCT": "S", "TCC": "S", "TCA": "S", "TCG": "S",
    "TAT": "Y", "TAC": "Y", "TAA": "*", "TAG": "*",
    "TGT": "C", "TGC": "C", "TGA": "*", "TGG": "W",

    "CTT": "L", "CTC": "L", "CTA": "L", "CTG": "L",
    "CCT": "P", "CCC": "P", "CCA": "P", "CCG": "P",
    "CAT": "H", "CAC": "H", "CAA": "Q", "CAG": "Q",
    "CGT": "R", "CGC": "R", "CGA": "R", "CGG": "R",

    "ATT": "I", "ATC": "I", "ATA": "I", "ATG": "M",
    "ACT": "T", "ACC": "T", "ACA": "T", "ACG": "T",
    "AAT": "N", "AAC": "N", "AAA": "K", "AAG": "K",
    "AGT": "S", "AGC": "S", "AGA": "R", "AGG": "R",

    "GTT": "V", "GTC": "V", "GTA": "V", "GTG": "V",
    "GCT": "A", "GCC": "A", "GCA": "A", "GCG": "A",
    "GAT": "D", "GAC": "D", "GAA": "E", "GAG": "E",
    "GGT": "G", "GGC": "G", "GGA": "G", "GGG": "G",
}


def base62_decode(data: str) -> bytes:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    num = 0
    for char in data:
        num = num * 62 + alphabet.index(char)

    return num.to_bytes((num.bit_length() + 7) // 8, "big")


def base45_decode(data: bytes) -> bytes:
    result = bytearray()
    i = 0

    while i < len(data):
        if i + 2 < len(data):
            x = (
                BASE45_ALPHABET.index(chr(data[i]))
                + BASE45_ALPHABET.index(chr(data[i + 1])) * 45
                + BASE45_ALPHABET.index(chr(data[i + 2])) * 45 * 45
            )

            result.append(x // 256)
            result.append(x % 256)
            i += 3

        else:
            x = (
                BASE45_ALPHABET.index(chr(data[i]))
                + BASE45_ALPHABET.index(chr(data[i + 1])) * 45
            )

            result.append(x)
            i += 2

    return bytes(result)


def translate_weird_dna(text: str) -> str:
    words = []

    for word in text.split():
        decoded = []
        i = 0

        while i < len(word):
            char = word[i]

            # Huruf O dan U di sini bukan base DNA normal.
            # Dari pola challenge, dua huruf ini sengaja disisipkan
            # sebagai karakter literal.
            if char in "OU":
                decoded.append(char)
                i += 1
                continue

            codon = word[i:i + 3]

            if codon not in CODON_TABLE:
                raise ValueError(f"Unknown codon: {codon}")

            decoded.append(CODON_TABLE[codon])
            i += 3

        words.append("".join(decoded))

    return " ".join(words)


def main():
    raw = EMOJI_FILE.read_text(encoding="utf-8").strip()

    # Emoji 🐗 muncul sebagai separator.
    chunks = raw.split("🐗")

    # Selain separator, terdapat tepat 16 emoji unik.
    # Ini cocok untuk representasi nibble 0x0 sampai 0xf.
    alphabet = sorted(set("".join(chunks)), key=ord)
    value = {emoji: index for index, emoji in enumerate(alphabet)}

    # Setiap token berisi 2 emoji = 1 byte.
    stage1 = bytes(
        (value[pair[0]] << 4) | value[pair[1]]
        for pair in chunks
    ).decode()

    # Onion layers.
    stage2 = base62_decode(stage1)
    stage3 = base45_decode(stage2)
    stage4 = base64.b32decode(stage3)
    stage5 = base64.b64decode(stage4).decode()

    message = translate_weird_dna(stage5)

    # Pesan hasil decode literalnya:
    # WEIRD AHH ONION ODFUSCATION
    #
    # Untuk flag final, typo "ODFUSCATION" dinormalisasi menjadi
    # "OBFUSCATION" karena konteks challenge jelas mengarah ke kata
    # "obfuscation".
    message = message.replace("ODFUSCATION", "OBFUSCATION")

    flag_body = message.lower().replace(" ", "_")
    flag = f"THEMCTF{{{flag_body}}}"

    print(flag)


if __name__ == "__main__":
    main()
