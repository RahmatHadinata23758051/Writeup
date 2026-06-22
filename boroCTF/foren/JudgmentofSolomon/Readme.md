# Judgment of Solomon — Forensics

**Flag:** `boroCTF{I_f1%ed_wHat_w4$_br0Ken}`

## Ringkas

File `code` bukan source code. Isinya satu stream hex panjang yang merepresentasikan raw RGB image 66x66. Ada string `boroCTF{...}` palsu yang disisipkan di tengah stream, jadi kalau cuma regex flag langsung kena decoy.

Setelah decoy dibuang, byte stream bisa dipecah menjadi 66 baris. Setiap baris berisi 198 byte RGB lalu delimiter `0x0a`, artinya ukuran gambarnya 66x66 piksel.

Image itu berisi QR code versi 4, tapi decoding biasa gagal karena channel yang benar harus dipilih. Channel merah dengan downsample 2x2 menghasilkan matrix QR 33x33 yang valid. QR tersebut memakai mask pattern 7 dan error correction level H, sesuai hint “Solomon” ke Reed-Solomon.

## Langkah

### 1. Recon awal

```bash
file code
wc -c code
python3 - <<'PY'
from pathlib import Path
s = Path('code').read_text(errors='ignore')
print(s[:100])
print(s.count('\n'))
print(set(s))
PY
```

File terbaca sebagai ASCII text. Karakternya dominan `F`, `0`, dan `A`, cocok sebagai dump hex untuk piksel hitam-putih/warna.

### 2. Decoy flag

```bash
python3 - <<'PY'
from pathlib import Path
s = Path('code').read_text(errors='ignore')
idx = s.find('boroCTF')
print(idx)
print(s[idx-80:idx+120])
PY
```

String `boroCTF{I_C0xL6n"+_d0_it_St11nz_n0w_go}` muncul langsung di tengah hex stream. Setelah dites, ini bukan flag valid.

### 3. Rekonstruksi raw image

Decoy dibuang dulu, lalu hex diubah menjadi bytes.

```python
hex_stream = re.sub(r"boroCTF\{[^}]+\}", "", hex_stream, count=1)
raw = bytes.fromhex(hex_stream)
rows = raw.split(b"\n")[:-1]
```

Hasilnya:

```text
66 rows
198 bytes per row
```

Karena 198 = 66 * 3, formatnya RGB 66x66.

### 4. Ambil QR matrix dari red channel

Setiap module QR digambar sebagai blok 2x2 piksel. Dari red channel, threshold `R < 128` dan downsample 2x2 menghasilkan matrix 33x33. Ukuran 33x33 cocok dengan QR version 4.

QR normal decoder masih gagal, jadi parsing dilakukan manual:

- QR version: 4
- Error correction: H
- Mask pattern: 7
- Reed-Solomon blocks: 4 block, masing-masing 9 data codeword + 16 EC codeword

### 5. Decode Reed-Solomon dan byte mode

Setelah data module dibaca mengikuti traversal QR standar, mask 7 dihapus, codeword dideinterleave, lalu setiap block didecode dengan Reed-Solomon.

```bash
python3 solve.py
```

Output:

```text
boroCTF{I_f1%ed_wHat_w4$_br0Ken}
```
