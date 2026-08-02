# me fr

## Challenge Information

- **Title:** me fr
- **Category:** Misc

## Description

> monkey type has nothing on me fr no cap

Challenge memberikan sebuah file berisi teks berikut:

```text
Jo! Sp O was tjomlomg/// tu[omg os kist sp jard mpwadaus! :pplomg at upir jamds wjo;e upi tu[e os omfiroatomg. Amuwaus. jeres tje f;ag" :3AL}WJU+D-+1+dP+TJ1S+s-+-f83M///|
```

---

## Analysis

Sekilas teks terlihat seperti hasil salah ketik acak. Namun setelah memperhatikan beberapa kata, terlihat bahwa sebagian besar huruf masih membentuk pola bahasa Inggris.

Beberapa contoh yang langsung terlihat:

| Ciphertext | Plaintext |
|------------|-----------|
| `Jo` | `Hi` |
| `Sp` | `So` |
| `tjomlomg` | `thinking` |
| `tu[omg` | `typing` |
| `:pplomg` | `Looking` |
| `upir` | `your` |
| `jamds` | `hands` |
| `wjo;e` | `while` |

Dari pola tersebut dapat disimpulkan bahwa hanya tombol yang biasanya ditekan menggunakan **tangan kanan** pada keyboard QWERTY yang bergeser **satu posisi ke kanan**.

Sebagai contoh:

| Karakter Salah | Karakter Asli |
|----------------|---------------|
| `J` | `H` |
| `o` | `i` |
| `p` | `o` |
| `u` | `y` |
| `[` | `p` |
| `l` | `k` |
| `;` | `l` |
| `m` | `n` |
| `/` | `.` |

Pergeseran tersebut juga berlaku pada simbol keyboard:

| Ciphertext | Plaintext |
|------------|-----------|
| `"` | `:` |
| `}` | `{` |
| `+` | `_` |
| `-` | `0` |
| `|` | `}` |

Dengan membalik seluruh pergeseran tersebut, plaintext asli dapat direkonstruksi.

---

## Solver

Simpan script berikut sebagai `solve.py`:

```python
#!/usr/bin/env python3
from pathlib import Path
import re
import sys


def create_decoder() -> dict[str, str]:
    decoder: dict[str, str] = {}

    keyboard_rows = [
        ("67890-", "7890-="),
        ("^&*()_", "&*()_+"),

        ("yuiop[]", "uiop[]\\"),
        ("YUIOP{}", "UIOP{}|"),

        ("hjkl;", "jkl;'"),
        ("HJKL:", 'JKL:"'),

        ("nm,.", "m,./"),
        ("NM<>", "M<>?"),
    ]

    for correct, mistyped in keyboard_rows:
        if len(correct) != len(mistyped):
            raise ValueError("Mapping keyboard tidak valid")

        for original_char, typed_char in zip(correct, mistyped):
            decoder[typed_char] = original_char

    return decoder


def decode(ciphertext: str) -> str:
    decoder = create_decoder()
    return "".join(decoder.get(char, char) for char in ciphertext)


def main() -> None:
    filename = sys.argv[1] if len(sys.argv) > 1 else "me_fr.txt"
    path = Path(filename)

    if not path.exists():
        raise SystemExit(f"File tidak ditemukan: {filename}")

    ciphertext = path.read_text(encoding="utf-8").strip()
    plaintext = decode(ciphertext)

    print("[+] Decoded text:")
    print(plaintext)

    flags = re.findall(r"[A-Za-z0-9_]+\{[^}\n]+\}", plaintext)

    print("\n[+] Flag candidate:")
    if flags:
        for flag in flags:
            print(flag)
    else:
        print("Flag tidak ditemukan")


if __name__ == "__main__":
    main()
```

---

## Usage

Jalankan solver:

```bash
python3 solve.py me_fr.txt
```

---

## Output

Program menghasilkan plaintext berikut:

```text
Hi! So I was thinking... typing is just so hard nowadays! Looking at your hands while you type is infuriating. Anyways. heres the flag: L3AK{WHY_D0_1_dO_TH1S_s0_0f73N...}
```

Tiga titik (`...`) pada hasil decoding berasal langsung dari karakter `///` pada ciphertext dan bukan hasil modifikasi manual.

---

## Flag

```text
L3AK{WHY_D0_1_dO_TH1S_s0_0f73N...}
```
