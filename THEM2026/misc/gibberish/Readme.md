# Writeup - Gibberish

## Ringkasan

Attachment berisi 9999 karakter CJK. Isinya terlihat seperti teks Cina acak, tetapi semua karakter berada pada rentang Unicode yang berurutan dan jumlah karakter uniknya tepat 94. Angka 94 cocok dengan jumlah printable ASCII dari `!` sampai `~`, sehingga file ini sangat mungkin bukan bahasa alami, melainkan substitusi karakter.

Flag yang didapat:

```text
THEM?!CTF{³úºd»5c«f±$-§¹Uõ'}
```

## Analisis awal

File diperiksa sebagai UTF-8 biasa:

```bash
file txt
python3 - <<'PY'
from pathlib import Path
s = Path('txt').read_text(encoding='utf-8')
print(len(s), len(set(s)))
print(hex(min(map(ord, s))), hex(max(map(ord, s))))
PY
```

Hasil penting:

- Panjang teks: 9999 karakter.
- Karakter unik: 94.
- Rentang codepoint: `0x7c2a` sampai `0x7c87`.

Karena rentangnya tepat 94 karakter, setiap karakter CJK bisa dipetakan ke printable ASCII:

```python
ascii_program = ''.join(chr(33 + (ord(ch) - min_codepoint)) for ch in text)
```

Setelah dipetakan, hasilnya bukan teks biasa, tetapi program esolang Malbolge. Ini cocok dengan judul challenge `Gibberish`, karena source code Malbolge memang terlihat seperti teks acak.

## Validasi Malbolge

Malbolge menggunakan karakter printable ASCII. Instruksi valid ditentukan dari:

```python
(ord(char) + posisi) % 94
```

Opcode valid Malbolge adalah:

```text
4, 5, 23, 39, 40, 62, 68, 81
```

Dengan mapping `min_codepoint -> '!'`, semua 9999 karakter source valid sebagai program Malbolge.

## Eksploitasi / Solusi

Script `solve.py` melakukan langkah berikut:

1. Membaca file UTF-8.
2. Mengambil codepoint minimum dari karakter CJK.
3. Mengubah setiap karakter CJK menjadi printable ASCII.
4. Menjalankan interpreter Malbolge minimal.
5. Output Malbolge didecode sebagai UTF-8.

Command final:

```bash
python3 solve.py txt
```

Output:

```text
THEM?!CTF{³úºd»5c«f±$-§¹Uõ'}
```

## Kesimpulan

Challenge ini menyembunyikan program Malbolge dengan cara mengganti printable ASCII menjadi 94 karakter CJK berurutan. Setelah mapping Unicode dibalik dan program Malbolge dijalankan, outputnya langsung menghasilkan flag.
