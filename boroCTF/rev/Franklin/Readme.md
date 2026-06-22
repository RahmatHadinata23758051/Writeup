# Franklin

File `chall` ternyata bukan ELF, tapi font TrueType. `file chall` langsung nunjuk ke `TrueType Font data`, jadi arah analisisnya pindah ke tabel-tabel TTF, bukan disassembly binary biasa.

## Temuan inti

Perbandingan dengan `/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf` nunjukin perubahan riil ada di tabel `cmap`, `GSUB`, dan `head`. Bagian paling mencolok ada di `GSUB` karena font asli DejaVu Sans punya banyak lookup, sedangkan file challenge cuma punya satu lookup `liga`.

Lookup itu berisi satu rule ligature:

```text
b + oroCTF{fR4nkl1n_f0n7} -> asterisk
```

Kalau ditulis ulang dari nama glyph:

```text
b ['o', 'r', 'o', 'C', 'T', 'F', 'braceleft', 'f', 'R', 'four', 'n', 'k', 'l', 'one', 'n', 'underscore', 'f', 'zero', 'n', 'seven', 'braceright'] => asterisk
```

Nama glyph seperti `braceleft`, `four`, `underscore`, `zero`, dan `seven` tinggal dikonversi ke karakter biasa. Hasil gabungannya adalah flag.

## Langkah solve

1. Identifikasi format file.

```bash
file chall
```

Output penting:

```text
chall: TrueType Font data, 18 tables, 1st "FFTM", 26 names, Macintosh
```

2. Bandingkan dengan font DejaVu Sans asli supaya tahu tabel mana yang dimodifikasi.

```bash
python3 - <<'PY'
from fontTools.ttLib import TTFont
f1 = TTFont('chall')
f2 = TTFont('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf')
for t in sorted(f1.reader.tables):
    d1 = f1.getTableData(t)
    d2 = f2.getTableData(t)
    if d1 != d2:
        print(t, len(d1), len(d2))
PY
```

Output penting:

```text
GSUB 120 5598
cmap 5906 7056
head 54 54
```

3. Dump isi ligature dari `GSUB`.

```bash
python3 - <<'PY'
from fontTools.ttLib import TTFont
f = TTFont('chall')
st = f['GSUB'].table.LookupList.Lookup[0].SubTable[0]
for first, ligs in st.ligatures.items():
    print('first', first)
    for lig in ligs:
        print('components', lig.Component, '=>', lig.LigGlyph)
PY
```

Output:

```text
first b
components ['o', 'r', 'o', 'C', 'T', 'F', 'braceleft', 'f', 'R', 'four', 'n', 'k', 'l', 'one', 'n', 'underscore', 'f', 'zero', 'n', 'seven', 'braceright'] => asterisk
```

4. Automasi ekstraksi dengan `solve.py`.

```bash
python3 solve.py
```

Output:

```text
boroCTF{fR4nkl1n_f0n7}
```

## Flag

```text
boroCTF{fR4nkl1n_f0n7}
```
