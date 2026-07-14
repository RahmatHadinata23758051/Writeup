# Emojibius

- **CTF:** BroncoCTF
- **Category:** Misc
- **Difficulty:** Easy
- **Flag:** `bronco{em0j1s_r_cr1ng3}`

## Artefak

Challenge memberi dua file:

```text
artifact.png
intercepted_signals.txt
```

`artifact.png` menampilkan lima emoji di dahi:

```text
🍎 🦊 🍐 🐶 🎈
```

Di pipi terdapat susunan karakter 5×5:

```text
b r o n c
{ e m 0 j
1 s _ g 3
} a d f h
i k l p q
```

Judul `Emojibius` mengarah ke Polybius square. Lima emoji dipakai sebagai label baris dan kolom dalam urutan yang sama.

## Tabel Decode

|     | 🍎 | 🦊 | 🍐 | 🐶 | 🎈 |
|-----|----|----|----|----|----|
| 🍎 | b | r | o | n | c |
| 🦊 | { | e | m | 0 | j |
| 🍐 | 1 | s | _ | g | 3 |
| 🐶 | } | a | d | f | h |
| 🎈 | i | k | l | p | q |

Emoji pertama menentukan baris, emoji kedua menentukan kolom.

Contoh:

```text
🍎🍎 -> row 🍎, column 🍎 -> b
🍎🦊 -> row 🍎, column 🦊 -> r
🍎🍐 -> row 🍎, column 🍐 -> o
🍎🐶 -> row 🍎, column 🐶 -> n
🍎🎈 -> row 🍎, column 🎈 -> c
```

Lima token pertama langsung membentuk:

```text
bronc
```

Token keenam:

```text
🍎🍐 -> o
```

Prefix lengkapnya menjadi:

```text
bronco
```

## Decode Seluruh Transmission

Ciphertext:

```text
🍎🍎 🍎🦊 🍎🍐 🍎🐶 🍎🎈 🍎🍐
🦊🍎 🦊🦊 🦊🍐 🦊🐶 🦊🎈
🍐🍎 🍐🦊 🍐🍐
🍎🦊 🍐🍐 🍎🎈 🍎🦊 🍐🍎 🍎🐶 🍐🐶 🍐🎈
🐶🍎
```

Hasil per bagian:

```text
bronco
{em0j
1s_
r_cr1ng3
}
```

Setelah digabung:

```text
bronco{em0j1s_r_cr1ng3}
```

## Solver

```bash
python3 solve.py intercepted_signals.txt
```

Output:

```text
bronco{em0j1s_r_cr1ng3}
```

## Flag

```text
bronco{em0j1s_r_cr1ng3}
```
