#!/usr/bin/env python3
import re
import tarfile
from pathlib import Path

BASE = Path(__file__).resolve().parent
HANDOUT_TGZ = BASE / "misc_Embedded-encryptor.tar.gz"
HANDOUT_DIR = BASE / "extract" / "handout"

IV = bytes([
    0x10, 0x9a, 0x41, 0xbc, 0xa7, 0x71, 0xbd, 0x4b,
    0xe3, 0x52, 0x27, 0x71, 0x2f, 0xd8, 0x63, 0x98,
])

# Key recovered from the power trace using first-round AES CPA.
# It is not trusted blindly: the script re-encrypts the whole known plaintext
# from main.c and checks it byte-for-byte against output.txt.
RECOVERED_KEY = b"NNS{1e4k_by_pwr}"

RCON = [0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def ensure_handout() -> Path:
    if (HANDOUT_DIR / "zephyrapp" / "src" / "main.c").exists():
        return HANDOUT_DIR

    if not HANDOUT_TGZ.exists():
        raise FileNotFoundError(f"missing {HANDOUT_TGZ}")

    (BASE / "extract").mkdir(exist_ok=True)
    with tarfile.open(HANDOUT_TGZ, "r:gz") as tf:
        tf.extractall(BASE / "extract")
    return HANDOUT_DIR


def parse_c_string_literal(expr: str) -> bytes:
    # main.c uses one normal C string for havamal. Python unicode_escape gives the
    # same bytes for normal escapes, then encode back to UTF-8.
    return bytes(expr, "utf-8").decode("unicode_escape").encode("latin1").decode("utf-8").encode("utf-8")


def parse_plaintext_and_ciphertext(handout: Path):
    main_c = (handout / "zephyrapp" / "src" / "main.c").read_text(encoding="utf-8")
    out = (handout / "output.txt").read_text(errors="ignore")

    m = re.search(r"char\s+havamal\[\]\s*=\s*\"(.*?)\";", main_c, re.S)
    if not m:
        raise RuntimeError("could not find havamal plaintext in main.c")
    plaintext = parse_c_string_literal(m.group(1))

    # C sizeof(char[]) includes the trailing NUL. Firmware truncates to a whole
    # number of AES blocks: sizeof(havamal) / AES_BLOCKLEN.
    c_array = plaintext + b"\x00"
    block_count = len(c_array) // 16
    plaintext = c_array[: block_count * 16]

    hex_bytes = re.findall(r"\b[0-9a-fA-F]{2}\b", out)
    # Ignore timestamps such as 00:00:10; LOG_HEXDUMP lines contribute exactly
    # 16 bytes per block, and the block labels are textual.
    # Safer parser: only use indented hexdump payload lines.
    ct = bytearray()
    for line in out.splitlines():
        if "|" not in line:
            continue
        left = line.split("|", 1)[0]
        vals = re.findall(r"\b[0-9a-fA-F]{2}\b", left)
        if len(vals) == 16:
            ct.extend(int(x, 16) for x in vals)

    if len(ct) != len(plaintext):
        raise RuntimeError(f"plaintext/ciphertext length mismatch: {len(plaintext)} vs {len(ct)}")

    return plaintext, bytes(ct)


def parse_sbox(handout: Path):
    aes_c = (handout / "zephyrapp" / "src" / "aes.c").read_text(errors="ignore")
    m = re.search(r"static const uint8_t sbox\[256\]\s*=\s*\{(.*?)\};", aes_c, re.S)
    if not m:
        raise RuntimeError("could not parse AES S-box from aes.c")
    vals = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]{2}", m.group(1))]
    if len(vals) != 256:
        raise RuntimeError(f"bad S-box length: {len(vals)}")
    return vals


def key_expansion(key: bytes, sbox):
    nk, nb, nr = 4, 4, 10
    round_key = list(key) + [0] * (nb * (nr + 1) * 4 - 16)

    for i in range(nk, nb * (nr + 1)):
        temp = round_key[(i - 1) * 4:i * 4]
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [sbox[x] for x in temp]
            temp[0] ^= RCON[i // nk]
        for j in range(4):
            round_key[i * 4 + j] = round_key[(i - nk) * 4 + j] ^ temp[j]
    return round_key


def xtime(x):
    return ((x << 1) ^ (0x1B if x & 0x80 else 0)) & 0xFF


def aes_encrypt_block(block: bytes, key: bytes, sbox):
    # tiny-AES-C uses state_t[4][4] cast directly from buf, so the in-memory
    # layout is row-major here.
    state = [list(block[i * 4:(i + 1) * 4]) for i in range(4)]
    rk = key_expansion(key, sbox)

    def add_round_key(r):
        off = r * 16
        for i in range(4):
            for j in range(4):
                state[i][j] ^= rk[off + i * 4 + j]

    def sub_bytes():
        for i in range(4):
            for j in range(4):
                state[j][i] = sbox[state[j][i]]

    def shift_rows():
        state[0][1], state[1][1], state[2][1], state[3][1] = state[1][1], state[2][1], state[3][1], state[0][1]
        state[0][2], state[2][2] = state[2][2], state[0][2]
        state[1][2], state[3][2] = state[3][2], state[1][2]
        state[0][3], state[1][3], state[2][3], state[3][3] = state[3][3], state[0][3], state[1][3], state[2][3]

    def mix_columns():
        for i in range(4):
            t = state[i][0]
            tmp = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3]
            tm = state[i][0] ^ state[i][1]
            state[i][0] ^= xtime(tm) ^ tmp
            tm = state[i][1] ^ state[i][2]
            state[i][1] ^= xtime(tm) ^ tmp
            tm = state[i][2] ^ state[i][3]
            state[i][2] ^= xtime(tm) ^ tmp
            tm = state[i][3] ^ t
            state[i][3] ^= xtime(tm) ^ tmp
        for i in range(4):
            for j in range(4):
                state[i][j] &= 0xFF

    add_round_key(0)
    for r in range(1, 10):
        sub_bytes()
        shift_rows()
        mix_columns()
        add_round_key(r)
    sub_bytes()
    shift_rows()
    add_round_key(10)

    return bytes(x for row in state for x in row)


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes, sbox):
    out = bytearray()
    prev = iv
    for i in range(0, len(plaintext), 16):
        x = bytes(a ^ b for a, b in zip(plaintext[i:i + 16], prev))
        enc = aes_encrypt_block(x, key, sbox)
        out.extend(enc)
        prev = enc
    return bytes(out)


def main():
    handout = ensure_handout()
    plaintext, ciphertext = parse_plaintext_and_ciphertext(handout)
    sbox = parse_sbox(handout)

    print(f"[*] blocks: {len(ciphertext) // 16}")
    print("[*] validating CPA-recovered AES key against output.txt")

    encrypted = aes_cbc_encrypt(plaintext, RECOVERED_KEY, IV, sbox)
    if encrypted != ciphertext:
        raise SystemExit("[-] recovered key did not reproduce the ciphertext")

    flag = RECOVERED_KEY.decode()
    print("[+] ciphertext reproduced exactly")
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
