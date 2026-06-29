# Scảry Duck — Misc Writeup

## Ringkas

`challenge.mp4` punya ZIP terenkripsi yang ditempel setelah struktur MP4. Password ZIP diambil dari audio tone dan visual grid pada 3 detik terakhir. `flag.enc` tidak langsung berisi flag; hasil decode pertamanya masih marker `-0day-...-RCE-`. Payload di tengah marker itu adalah base62.

Flag final:

```text
V1T{7h47_dUck_l00k_5c4ry_7h0}
```

## Langkah solve

### 1. Ekstrak arsip awal

Arsip `scary_duck(2).7z` berisi satu file:

```text
challenge.mp4
```

### 2. Baca metadata video

```bash
ffprobe -v error -show_entries format_tags=comment -of default=nk=1:nw=1 challenge.mp4 | base64 -d
```

Output:

```text
Not everything -infiltrate- is in the frames you see. Examine the last 3 seconds of the -shellcode- video very carefully: both visually -malware-  and audibly. (and this file is 'bigger' -backdoor- than you think...)
```

Clue-nya jelas: cek visual, cek audio, dan cek ukuran file karena ada data appended.

### 3. Ambil password dari 3 detik terakhir

Audio terakhir berisi 8 tone. Peak frequency-nya:

```text
600, 2250, 1800, 2250, 900, 1200, 1050, 2700
```

Dengan base 600 Hz dan step 150 Hz, nilainya menjadi hex:

```text
0b8b243e
```

Frame terakhir menampilkan grid hitam-putih 4×8. Dibaca row-wise, bit-nya diinvert, lalu dikonversi ke hex:

```text
d6ee2fdd
```

Gabungan audio + visual:

```text
0b8b243ed6ee2fdd
```

Nilai ini dipakai sebagai password ZIP dan key XOR 8-byte.

### 4. Ambil ZIP tersembunyi

Parsing top-level MP4 box berhenti setelah `moov`. Byte setelahnya mulai dengan magic ZIP `PK\x03\x04`.

```bash
python3 - <<'PY'
from pathlib import Path
blob = Path('challenge.mp4').read_bytes()
idx = blob.find(b'PK\x03\x04')
Path('appended.bin').write_bytes(blob[idx:])
print(hex(idx))
PY
```

ZIP berisi:

```text
solver.py
flag.enc
```

Keduanya encrypted memakai password:

```text
0b8b243ed6ee2fdd
```

### 5. Decode `flag.enc`

`solver.py` menjelaskan urutan encode:

```text
reverse -> XOR repeating key -> base64
```

Dekodenya dibalik:

```text
base64 decode -> XOR repeating key -> reverse
```

Key XOR adalah byte dari hex password:

```python
bytes.fromhex("0b8b243ed6ee2fdd")
```

Hasil decode layer ini:

```text
-0day-I05Dqrhk0WASzcVa4EovsSduXJpFxRpKbjORsM9-RCE-
```

Ini belum flag final. Bagian tengahnya adalah payload base62:

```text
I05Dqrhk0WASzcVa4EovsSduXJpFxRpKbjORsM9
```

Decode base62 dengan alfabet `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`:

```python
alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
s = "I05Dqrhk0WASzcVa4EovsSduXJpFxRpKbjORsM9"
n = 0
for ch in s:
    n = n * 62 + alphabet.index(ch)
flag = n.to_bytes((n.bit_length() + 7) // 8, "big").decode()
print(flag)
```

Output:

```text
V1T{7h47_dUck_l00k_5c4ry_7h0}
```

### 6. Script final

```bash
python3 solve.py challenge.mp4
```

Output:

```text
<FLAG>V1T{7h47_dUck_l00k_5c4ry_7h0}</FLAG>
```
