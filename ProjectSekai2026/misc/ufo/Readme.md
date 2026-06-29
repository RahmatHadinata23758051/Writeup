# ufo — Reverse

Target berupa APK Android bernama **Universal File Opener**. String `SEKAI{...}` tidak disimpan langsung. String `Specialist formats handled cleanly.` sempat terlihat seperti kandidat, tapi itu cuma teks fitur/decoy dari daftar format yang didukung aplikasi.

Flag asli disembunyikan di jalur `ambient_trace`: aplikasi menyimpan progress fitur dalam bitmask, lalu ada canvas 21×21 yang dibangun dari beberapa layer tersembunyi. Setelah semua layer digabung, bit-bitnya bisa dibaca sebagai payload QR version 1.

## Langkah

### 1. Ekstrak APK

```bash
tar -xzf misc_ufo.tar.gz
cd misc_ufo
unzip -q app-release.apk -d extracted
```

Pencarian string langsung hanya menghasilkan noise library dan satu decoy:

```bash
strings -a extracted/classes2.dex | grep -i 'specialist\|sekai\|flag'
```

Decoy yang muncul:

```text
Specialist formats handled cleanly.
```

String ini ada di daftar supported formats, bukan jalur validasi flag.

### 2. Cari jalur yang tidak normal

Dari string dan xref DEX, bagian yang paling mencurigakan adalah key preferences berikut:

```text
ambient_trace
ambientTrace
recordAmbientTrace
recordAmbientTrace(Lcom/krauq/universalfileopener/data/AmbientTraceMark;)V
```

`ambient_trace` bertipe integer dan dipakai seperti bitmask. Enum mark yang terlihat:

```text
PdfSignature      -> 1
PdfMetadata       -> 2
OfficeText        -> 4
Spreadsheet       -> 8
ImageTransform    -> 16
```

Berarti state penuh adalah `1|2|4|8|16 = 0x1f`.

### 3. Decode layer ambient trace

Rutin drawing menyimpan 5 array byte. Tiap byte tidak langsung dipakai; app membuat key per indeks memakai operasi integer 32-bit, lalu byte di-xor dengan key tersebut.

Formula intinya:

```python
seed = ((layer + 1) * 461845907) ^ 1831565813
seed ^= ((i + 17) * -2048144789)
seed ^= seed >> 16
seed *= 2146121005
seed ^= seed >> 15
seed *= -2073254261
seed ^= seed >> 16
key = seed >> 24
plain_byte = encoded_byte ^ key
```

Hasil decode tiap layer adalah 441 bit, pas untuk grid `21×21`. Layer-layer ini kemudian digabung sesuai bitmask penuh:

```text
layer0 xor layer1 xor layer2 xor layer3 xor layer4 = xor1f
```

### 4. Baca sebagai QR v1 tanpa finder pattern

Grid 21×21 cocok dengan ukuran QR version 1. Finder pattern standar tidak muncul karena yang tersimpan hanya data modules/layer canvas, jadi decoding dilakukan manual:

- mark function modules QR v1: finder, separator, timing, format info, dark module
- ambil sisa 208 data bit dengan urutan zig-zag QR standar
- brute force QR mask pattern `0..7`
- parse bitstream QR byte mode

Hanya satu hasil yang valid:

```text
combine: xor1f
qr mask: 5
payload: clankedormiscgod
```

Soal meminta hasil dibungkus dengan `SEKAI{}`.

```text
SEKAI{clankedormiscgod}
```

## Script

`solve.py` mereplikasi proses decode layer, XOR semua ambient layer, membaca data modules QR v1, brute force mask QR, lalu mencetak flag.

```bash
python3 solve.py
```

Output:

```text
ambient layers: 5
combine: xor1f
qr mask: 5
SEKAI{clankedormiscgod}
```
