#!/usr/bin/env python3
"""Membalikkan enkripsi template C++ challenge secara langsung."""

KEY = [10, 21, 99, 4, 534, 24, 63, 57, 102, 38, 0, 123, 53, 674, 12, 57]
CIPHERTEXT = [221, 75, 97, 125, 30, 124, 51, 122, 15, 186, 39, 46, 74, 175, 120, 83, 219, 165]


def round_function(right: int, key_byte: int, state: int) -> int:
    """ZCHU: ((right + (key_byte * state + state)) * 17) % 135."""
    return ((right + key_byte * state + state) * 17) % 135


def decrypt_pair(left: int, right: int, state: int) -> tuple[int, int]:
    # Enkripsi: (L, R) -> (R, L ^ F(R)); balikkan dalam urutan key terbalik.
    for key_byte in reversed(KEY):
        left, right = right ^ round_function(left, key_byte, state), left
    return left, right


def encrypt_pair(left: int, right: int, state: int) -> tuple[int, int]:
    for key_byte in KEY:
        left, right = right, left ^ round_function(right, key_byte, state)
    return left, right


def main() -> None:
    state = 1
    plaintext = []
    verification = []

    for cipher_left, cipher_right in zip(CIPHERTEXT[::2], CIPHERTEXT[1::2]):
        plain_left, plain_right = decrypt_pair(cipher_left, cipher_right, state)
        plaintext.extend((plain_left, plain_right))
        verification.extend(encrypt_pair(plain_left, plain_right, state))
        state += cipher_left + cipher_right

    assert verification == CIPHERTEXT
    print(f"<FLAG>{bytes(plaintext).decode('ascii')}</FLAG>")


if __name__ == "__main__":
    main()
