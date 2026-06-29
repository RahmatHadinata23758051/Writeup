# Enc — Reverse Engineering Writeup

## Ringkasan

`enc.exe` adalah binary .NET 8 NativeAOT. Program mengenkripsi `flag.png` dengan dua lapis cipher:

1. AES-256-ECB dengan padding PKCS#7.
2. ChaCha7539 dari BouncyCastle.

Key AES, key ChaCha, dan nonce tidak disimpan langsung. Program membentuk ketiganya dari dua string hexadecimal yang berada di region `hydrated` milik NativeAOT. Setelah region itu direkonstruksi dan proses derivasi key diulang, `flag.enc` dapat dibalik menjadi PNG asli.

Flag:

```text
v1t{1_am_Gu1lty_0xf_Making.NetAOT:(!}
```

## Enumerasi

Isi arsip hanya terdiri dari binary dan ciphertext:

```bash
unzip -l bin.zip
file bin/enc.exe bin/flag.enc
sha256sum bin/enc.exe bin/flag.enc
```

Hasil penting:

```text
enc.exe:  PE32+ executable (console) x86-64, .NET NativeAOT
flag.enc: data, 7808 bytes
```

Panjang `flag.enc` habis dibagi 16. Ini sesuai dengan keluaran AES block cipher sebelum dibungkus stream cipher.

## Memetakan `Program.Main`

Disassembly `Program.Main` memperlihatkan pemakaian class berikut:

```text
System.Security.Cryptography.Aes
Org.BouncyCastle.Crypto.Engines.ChaCha7539Engine
Org.BouncyCastle.Crypto.Parameters.KeyParameter
Org.BouncyCastle.Crypto.Parameters.ParametersWithIV
```

Alur enkripsinya:

```text
hex seed ──> IV 16 byte + key AES 32 byte
hex material ──> AES-256-CBC/PKCS7 encrypt ──> derived bytes

AES key    = derived[0:32]
ChaCha key = derived[32:64]
nonce      = derived[64:76]

flag.png ──PKCS7──> AES-256-ECB ──> ChaCha7539 ──> flag.enc
```

Operasi terakhir ChaCha bersifat XOR, sehingga fungsi yang sama dipakai saat enkripsi dan dekripsi.

## Mengambil string dari NativeAOT

Dua string hexadecimal tidak muncul sebagai plaintext normal di file. Keduanya berada di section virtual `hydrated`, sedangkan representasi terkompresinya disimpan pada ReadyToRun section type `207` (`DehydratedData`).

`StartupCodeHelpers.RehydrateData` memakai command stream dengan enam jenis operasi:

| Opcode | Operasi |
|---:|---|
| 0 | Salin byte literal ke destination |
| 1 | Lewati area destination yang bernilai nol |
| 2 | Tulis satu relative pointer dari fixup table |
| 3 | Tulis satu absolute pointer dari fixup table |
| 4 | Tulis rangkaian relative pointer inline |
| 5 | Tulis rangkaian absolute pointer inline |

Byte command memakai tiga bit rendah sebagai opcode. Lima bit atas menyimpan panjang. Nilai panjang di atas 28 memakai satu sampai tiga byte tambahan.

Setelah stream direkonstruksi, objek `System.String` dibaca memakai layout x64 berikut:

```text
+0x00  MethodTable pointer
+0x08  uint32 character count
+0x0c  UTF-16LE characters
```

Alamat yang direferensikan oleh `Program.Main`:

```text
0x290128  seed hexadecimal
0x2a1768  material hexadecimal
```

Nilai yang dipulihkan:

```text
seed = 926c3b1ec823f9414596ac39cbedb742f
       6b3e9a9411517da358c4f93ff630841b
       d3aea9a1010941ab48117ca1faa7c85

material = ba6168403341c29303bbe73e9b9c5ee1
           636ccc4e63d7e3fcbcc24a96de1569a8
           d588ffe4caf4541165281f7aada9eaf6
           6ff2b3c527232a1fce8a56fa3ece728a
           769b3e816ec195fee556dc18
```

`seed` berukuran 48 byte: 16 byte pertama adalah IV CBC dan 32 byte berikutnya adalah key AES. `material` berukuran 76 byte. Setelah dienkripsi AES-CBC dengan PKCS#7, hasilnya berukuran 80 byte dan dipotong menjadi key-key akhir.

## Membalik Enkripsi

Urutan dekripsi harus dibalik:

```text
flag.enc
  └─ ChaCha7539 XOR, counter awal 0
      └─ AES-256-ECB decrypt
          └─ hapus PKCS#7
              └─ flag.png
```

Validasi hasil:

```text
PNG size    : 7794 bytes
PNG SHA-256 : 390c723f9788d6ecf69f87ee564e72994c4f3480e80faa31d52507b12e5febc1
Signature   : 89 50 4e 47 0d 0a 1a 0a
Dimensions  : 1100 x 513
```

Teks flag dirender langsung sebagai piksel di dalam gambar, bukan disimpan pada chunk metadata PNG.

## Solver

Aktifkan environment lalu jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py bin.zip
```

Output:

```text
[+] recovered PNG: .../flag.png
[+] SHA-256: 390c723f9788d6ecf69f87ee564e72994c4f3480e80faa31d52507b12e5febc1
<FLAG>v1t{1_am_Gu1lty_0xf_Making.NetAOT:(!}</FLAG>
```

Solver tidak menanamkan key hasil analisis. Ia membaca PE, menemukan ReadyToRun section type 207, menjalankan ulang format `RehydrateData`, mengambil dua `System.String`, dan melakukan seluruh derivasi serta dekripsi secara otomatis. Transkripsi flag baru dicetak jika digest PNG hasil dekripsi cocok dengan artefak yang sudah divalidasi.
