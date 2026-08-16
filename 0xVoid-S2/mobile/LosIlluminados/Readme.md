# LosIlluminados

## Ringkasan

Flag ada di asset `assets/illuminados_signal.bin`, bukan di `NOTICE.txt`. APK menyimpan receiver `los.illuminados.IlluminadosReceiver` yang hanya aktif untuk action `com.los.illuminados.RECEIVE`. Receiver membaca signal bundle, mengambil payload setelah header, menurunkannya dengan key dari HMAC-SHA256, lalu menulis plaintext ke `Log.d("LosIlluminados", ...)`.

Hasil decrypt berupa JSON:

```json
{"channel":"los/illuminados/primary","seq":13,"flag":"0xV0ID{l0s_1llum1n4d0s_h4v3_sp0tt3d_y0u}","auth":"verified"}
```

## File Challenge

File utama:

```
LosIlluminados.apk
```

Isi APK:

```
classes.dex
AndroidManifest.xml
resources.arsc
assets/NOTICE.txt
assets/illuminados_signal.bin
META-INF/DEBUG.SF
META-INF/DEBUG.RSA
META-INF/MANIFEST.MF
```

`NOTICE.txt` berisi decoy:

```
0xV0ID{the_notice_file_is_a_trap}
```

Flag itu tidak valid karena app sendiri memakai asset `illuminados_signal.bin`.

## Analisis Awal

Identifikasi awal:

```bash
file *
unzip -l LosIlluminados.apk
strings -a apk/classes.dex
```

`file` menunjukkan APK Android dengan `classes.dex`. Dari `strings` di `classes.dex` terlihat string penting:

```
HmacSHA256
Llos/illuminados/IlluminadosDecoder;
Llos/illuminados/IlluminadosReceiver;
decryptBundle
deriveKey
onReceive
illuminados_signal.bin
com.los.
illuminados.
RECEIVE
|Illuminados
Receiver
```

Asset signal punya format awal:

```
4c 4f 53 49 4c 01 00 ...
L  O  S  I  L  01 00
```

Jadi header bundle:

```
magic   = "LOSIL"
version = 0x01
reserved/unused byte = 0x00
payload dimulai offset 7
```

## Analisis Static

APK kecil, jadi `classes.dex` bisa dibaca langsung. Dua class yang relevan:

```
los.illuminados.IlluminadosReceiver
los.illuminados.IlluminadosDecoder
```

Manifest menunjukkan package app:

```
los.illuminados
```

Receiver class:

```
los.illuminados.IlluminadosReceiver
```

Intent action:

```
com.los.illuminados.RECEIVE
```

Alur `onReceive()`:

```
intent.getAction()
cek action == "com.los.illuminados.RECEIVE"
deriveKey(context)
buka assets/illuminados_signal.bin
cek byte[5] == 1
copy payload dari offset 7 sampai akhir
decryptBundle(payload, key)
new String(plaintext)
Log.d("LosIlluminados", plaintext)
```

`deriveKey(context)` membangun dua string:

```
message  = context.getPackageName() + "|Illuminados" + "Receiver"
hmac_key = "com.los." + "illuminados." + "RECEIVE"
```

Dengan package dari manifest, nilainya menjadi:

```
message  = "los.illuminados|IlluminadosReceiver"
hmac_key = "com.los.illuminados.RECEIVE"
```

Key final:

```
HMAC-SHA256(key=hmac_key, msg=message)
```

`decryptBundle(payload, key)` melakukan dua tahap:

```
1. Pair-swap payload:
   out[i]   = payload[i + 1]
   out[i+1] = payload[i]
   untuk i = 0, 2, 4, ...

2. XOR semua byte hasil swap dengan key berulang:
   plaintext[i] = swapped[i] ^ key[i % 32]
```

## Analisis Dynamic

APK tidak perlu dijalankan di emulator. Receiver hanya membaca asset lokal dan menulis hasil decrypt ke Android log. Logic itu direplikasi di `solve.py` supaya prosesnya bisa dijalankan ulang langsung dari APK.

Validasi lokal:

```bash
./solve.py
```

Output:

```
{"channel":"los/illuminados/primary","seq":13,"flag":"0xV0ID{l0s_1llum1n4d0s_h4v3_sp0tt3d_y0u}","auth":"verified"}
0xV0ID{l0s_1llum1n4d0s_h4v3_sp0tt3d_y0u}
```

Plaintext JSON punya field `auth` bernilai `verified`, jadi ini bukan decoy dari `NOTICE.txt`.

## Algoritma Validasi atau Encoding

Tidak ada input flag yang divalidasi user. Challenge ini menyembunyikan flag sebagai encrypted signal bundle.

Format bundle:

```
offset 0..4  : magic "LOSIL"
offset 5     : version, harus 1
offset 6     : byte tidak dipakai oleh receiver
offset 7..N  : ciphertext
```

Key derivation:

```python
key = HMAC_SHA256(
    key=b"com.los.illuminados.RECEIVE",
    msg=b"los.illuminados|IlluminadosReceiver"
)
```

Decrypt:

```python
swapped = pair_swap(ciphertext)
plaintext = swapped XOR repeating_key
```

## Penyusunan Solve Script

`solve.py` dibuat supaya membaca APK langsung, tanpa perlu ekstrak manual:

1. Buka `LosIlluminados.apk` dengan `zipfile`.
2. Parse package name dari binary `AndroidManifest.xml`.
3. Ambil `assets/illuminados_signal.bin`.
4. Validasi magic `LOSIL` dan version `1`.
5. Turunkan HMAC key sesuai logic `deriveKey()`.
6. Jalankan pair-swap + XOR sesuai `decryptBundle()`.
7. Parse JSON dan cetak field `flag`.

## Cara Menjalankan

Dari folder challenge:

```bash
chmod +x solve.py
./solve.py
```

Atau:

```bash
python3 solve.py
```

## Flag

```
0xV0ID{l0s_1llum1n4d0s_h4v3_sp0tt3d_y0u}
```
