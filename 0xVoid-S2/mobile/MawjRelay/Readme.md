# Mawj Relay

## Ringkasan

APK kecil ini menyamarkan data notifikasi di `assets/push_routes.bin`. File
lainnya berisi decoy: `README_NOTE.txt`, `debug_flag`, dan DEX palsu.

## File Challenge

- `kizcjo.apk`
- `assets/push_routes.bin` setelah ekstraksi APK

## Analisis Awal

Manifest mendefinisikan package `void.mobile.echopush`, label `EchoPush`, dan
receiver untuk action `com.void.echo.PUSH`. APK tidak memakai kompresi ZIP.

`classes.dex` hanya berisi header DEX dan string decoy, tetapi struktur DEX-nya
tidak valid sehingga tidak dapat didecompile. `README_NOTE.txt` secara
eksplisit menyatakan dirinya decoy. Resource juga memberi petunjuk:

```text
key = sha256(action + ':' + label)
```

## Analisis Static

`push_routes.bin` diawali dengan:

```text
VPUSH1 00 00 81
```

Byte `0x81` menyatakan panjang payload terenkripsi, yaitu 129 byte. Empat byte
setelah payload adalah checksum CRC32 big-endian.

## Algoritma Validasi atau Encoding

Key dihitung dari data manifest/resource:

```text
sha256("com.void.echo.PUSH:EchoPush")
```

Payload di-XOR dengan key tersebut secara berulang setiap 32 byte. Hasilnya
adalah JSON:

```json
{"route":"prod/receiver/primary","priority":42,"flag":"0xV01D{push_receiver_xor_is_not_crypto}","crc32":"verified after decrypt"}
```

CRC32 plaintext adalah `07ae8260`, sama dengan checksum yang tersimpan di
asset, sehingga hasil dekripsi tervalidasi.

## Penyusunan Solve Script

`solve.py` membaca asset, mengambil panjang payload, menghitung SHA-256 key,
melakukan repeating-key XOR, memeriksa CRC32, lalu mengambil field `flag` dari
JSON.

## Cara Menjalankan

```bash
unzip -q kizcjo.apk -d extracted
python3 solve.py
```

## Flag

```text
0xV01D{push_receiver_xor_is_not_crypto}
```

## Catatan

Flag pada `README_NOTE.txt`, `debug_flag`, dan `FAKE_FLAG` di DEX adalah decoy
dan tidak digunakan oleh payload route yang tervalidasi.
