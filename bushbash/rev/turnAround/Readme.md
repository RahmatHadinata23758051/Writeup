# Turned Around

## Informasi Challenge

| Field | Value |
|-------|-------|
| **Kategori** | Reverse Engineering |
| **Judul** | Turned Around |
| **Artifact** | `turnedaround.bf` |
| **Format Flag** | `bushbash{password}` |

---

# Ringkasan

Challenge memberikan sebuah program **Brainfuck** yang sekilas hanya mencetak pesan palsu ketika dijalankan. Tidak ada mekanisme input maupun validasi password selama eksekusi.

Analisis terhadap source menunjukkan bahwa password sebenarnya disembunyikan di dalam **loop Brainfuck yang tidak pernah dieksekusi**. Dengan mengekstrak isi loop tersebut dan menjalankannya secara terpisah, dua potongan password berhasil diperoleh dan digabungkan menjadi flag.

---

# Deskripsi Challenge

Deskripsi challenge menyebutkan bahwa sebuah perangkat terinfeksi malware dan password root kemungkinan masih tersimpan di dalam source code.

Menjalankan program secara normal hanya menghasilkan pesan:

```text
Nice try! Unfortunately it's not that easy...
```

Karena output tersebut jelas merupakan umpan, password harus dicari melalui analisis source.

---

# Analisis Awal

Brainfuck hanya memiliki delapan instruksi:

```text
>
<
+
-
.
,
[
]
```

Setelah membersihkan file dari karakter selain instruksi Brainfuck, terlihat bahwa program **tidak menggunakan instruksi input `,`**.

Artinya program tidak pernah membaca input pengguna sehingga password tidak mungkin diperiksa saat runtime. Dengan demikian password kemungkinan besar sudah tertanam langsung di dalam source.

---

# Mencari Cabang Mati

Source mengandung beberapa blok seperti:

```brainfuck
[]
```

dan

```brainfuck
[
    ...
]
```

Pada Brainfuck, loop memiliki perilaku:

```text
[
    ...
]
```

akan dijalankan **hanya jika sel saat ini bernilai bukan nol**.

Karena tape Brainfuck selalu diawali dengan nilai nol, seluruh blok tersebut langsung dilewati.

Dengan kata lain, isi loop merupakan **dead code** yang tidak pernah dieksekusi pada jalur normal.

---

# Mengeksekusi Isi Loop

Setiap body loop diekstrak menjadi program Brainfuck tersendiri kemudian dijalankan menggunakan interpreter sederhana.

Sebagian besar loop tidak menghasilkan apa pun, tetapi dua di antaranya mencetak string yang dapat dibaca.

Output pertama:

```text
Core Dumped!
Recovered partial password:

(d0Ub13*_______
```

Bagian password yang diperoleh:

```text
(d0Ub13*
```

---

Output kedua:

```text
TODO:
Remove this note where I hide half my hidden password:

________-*b4ck!
```

Bagian password kedua:

```text
-*b4ck!
```

---

# Rekonstruksi Password

Kedua bagian digabungkan:

```text
(d0Ub13*
+
-*b4ck!
```

Hasil akhirnya:

```text
(d0Ub13*-*b4ck!
```

Sehingga flag menjadi:

```text
bushbash{(d0Ub13*-*b4ck!}
```

---

# Solver

```python
#!/usr/bin/env python3

import re
import sys

BF_CHARS = set("><+-.,[]")


def clean_bf(src):
    return "".join(c for c in src if c in BF_CHARS)


def build_bracket_map(code):
    stack = []
    pair = {}

    for i, c in enumerate(code):
        if c == "[":
            stack.append(i)

        elif c == "]":
            if not stack:
                raise ValueError("Unmatched ]")

            j = stack.pop()
            pair[i] = j
            pair[j] = i

    if stack:
        raise ValueError("Unmatched [")

    return pair


def run_bf(code):
    pair = build_bracket_map(code)

    tape = [0] * 30000
    ptr = 0
    pc = 0

    out = []

    while pc < len(code):
        op = code[pc]

        if op == ">":
            ptr += 1
            if ptr >= len(tape):
                tape.append(0)

        elif op == "<":
            ptr -= 1

        elif op == "+":
            tape[ptr] = (tape[ptr] + 1) & 0xff

        elif op == "-":
            tape[ptr] = (tape[ptr] - 1) & 0xff

        elif op == ".":
            out.append(chr(tape[ptr]))

        elif op == ",":
            tape[ptr] = 0

        elif op == "[":
            if tape[ptr] == 0:
                pc = pair[pc]

        elif op == "]":
            if tape[ptr] != 0:
                pc = pair[pc]

        pc += 1

    return "".join(out)


def printable(text):
    if not text:
        return False

    ok = sum(
        c in "\n\r\t" or 32 <= ord(c) < 127
        for c in text
    )

    return ok / len(text) > 0.85


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} turnedaround.bf")
        return

    with open(sys.argv[1]) as f:
        code = clean_bf(f.read())

    pair = build_bracket_map(code)

    print("[+] Normal output")
    print(run_bf(code))

    outputs = []

    for start in sorted(i for i, c in enumerate(code) if c == "["):
        end = pair[start]
        block = code[start + 1:end]

        try:
            result = run_bf(block)
        except Exception:
            continue

        if printable(result):
            outputs.append(result.strip())

    joined = "\n".join(outputs)

    left = re.search(
        r"Recovered partial password:\s*([^\s_]+)_+",
        joined,
    )

    right = re.search(
        r"hidden password:\s*_+([^\s]+)",
        joined,
    )

    password = left.group(1) + right.group(1)

    print()
    print("[+] Password:", password)
    print("[+] Flag:", f"bushbash{{{password}}}")


if __name__ == "__main__":
    main()
```

---

# Menjalankan Solver

```bash
python3 solver.py turnedaround.bf
```

Output:

```text
[+] Password:
(d0Ub13*-*b4ck!

[+] Flag:
bushbash{(d0Ub13*-*b4ck!}
```

---

# Alur Penyelesaian

```text
Program Brainfuck
        │
        ▼
Eksekusi normal
        │
        ▼
Hanya mencetak pesan palsu
        │
        ▼
Analisis source
        │
        ▼
Menemukan loop yang tidak pernah dieksekusi
        │
        ▼
Ekstrak isi setiap loop
        │
        ▼
Jalankan sebagai program Brainfuck terpisah
        │
        ▼
Dapat dua potongan password
        │
        ▼
Gabungkan password
        │
        ▼
Peroleh flag
```

---

# Flag

```text
bushbash{(d0Ub13*-*b4ck!}
```
