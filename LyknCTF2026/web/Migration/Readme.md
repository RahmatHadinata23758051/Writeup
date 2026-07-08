# Migrant

**Category:** Web  
**CTF:** LYKNCTF 2026  
**Target:** `http://dff994e4-0937-43b6-b739-4c269fddab25.51.79.140.18.nip.io:8080/`  
**Flag:** `LYKNCTF{424b7d98da72494bb08e2645eb435e92}`

## Deskripsi

> The company currently changed their brand identity, and all staff must migrate their accounts to this new website. But... something is off with the transfer function.

Website menyediakan token migrasi terenkripsi untuk akun guest:

```text
8FoFckHS2JB/2zBGtXpSCHSc4m8fAGkNrqdmeHieuem9/yW1NknM0TiWJvuQsRdQ/ymJM+zY35r6DEJOc+x1Fg==
```

Token dikirim ke endpoint berikut:

```http
POST /api/migrate
Content-Type: application/json

{"token":"..."}
```

Token asli menghasilkan profil biasa:

```json
{
  "message": "Migration successful.",
  "profile": {
    "role": "user",
    "user": "guest",
    "v": "1.0"
  }
}
```

Targetnya mengubah field `role` menjadi `admin` tanpa mengetahui key enkripsi.

## Recon

Token Base64 didekode menjadi 64 byte:

```text
block 0: f05a057241d2d8907fdb3046b57a5208
block 1: 749ce26f1f00690daea76678789eb9e9
block 2: bdff25b53649ccd1389626fb90b11750
block 3: ff298933ecd8df9afa0c424e73ec7516
```

Ukuran blok 16 byte dan total empat blok cocok dengan struktur AES-CBC:

```text
IV || C1 || C2 || C3
```

Mengubah byte terakhir token selalu menghasilkan respons berbeda:

```json
{"error":"Token corrupted, invalid padding"}
```

Server membedakan ciphertext dengan padding valid dan padding tidak valid. Perbedaan respons ini membentuk **padding oracle**.

## Padding Oracle

Untuk satu blok ciphertext `C`, plaintext dihitung sebagai:

```text
P = D(C) XOR Cprev
```

Nilai `D(C)` disebut intermediate state. Intermediate state bisa dipulihkan byte per byte dengan memodifikasi blok sebelumnya dan mengamati apakah PKCS#7 padding diterima server.

Untuk mencari byte terakhir, blok sebelumnya diubah sampai plaintext terakhir menjadi:

```text
01
```

Setelah byte terakhir ditemukan, dua byte terakhir dipaksa menjadi:

```text
02 02
```

Proses yang sama dilanjutkan sampai seluruh 16 byte intermediate state diketahui.

Karena oracle hanya memeriksa dua blok terakhir yang dikirim, payload probe dibuat seperti ini:

```text
00...00 || 00...00 || crafted_previous || target_block
```

Dua blok nol di depan hanya menjaga format token tetap empat blok.

## Mendekripsi Token

Intermediate state untuk `C1` dan `C2` dipulihkan dengan oracle, lalu plaintext dihitung:

```text
P1 = D(C1) XOR IV
P2 = D(C2) XOR C1
```

Dua blok plaintext pertama yang ditemukan:

```text
{"user":"guest", "role":"user", 
```

Pembagian per blok:

```text
P1 = b'{"user":"guest", '
P2 = b'"role":"user", '
```

## Forge Role Admin

Mengganti `user` menjadi `admin` menambah satu byte. Panjang plaintext harus tetap sama agar struktur blok berikutnya tidak bergeser.

Payload target dibuat menjadi:

```text
P1' = b'{"user":"gues", '
P2' = b'"role":"admin", '
```

Username dipendekkan satu byte dan satu spasi sebelum `role` dihapus. Total panjang dua blok tetap 32 byte.

Untuk memaksa `P2` menjadi `P2'`, blok `C1` dimodifikasi:

```text
C1' = C1 XOR P2 XOR P2'
```

CBC bersifat malleable, jadi perubahan pada `C1` langsung mengubah plaintext blok kedua. Efek sampingnya, plaintext blok pertama ikut rusak karena `C1'` juga merupakan ciphertext yang didekripsi menjadi blok pertama.

Kerusakan blok pertama diperbaiki dengan:

1. Memulihkan `D(C1')` menggunakan padding oracle.
2. Menghitung IV baru agar plaintext blok pertama menjadi `P1'`.

Rumusnya:

```text
IV' = D(C1') XOR P1'
```

Token final:

```text
IV' || C1' || C2 || C3
```

Hasil forge dalam Base64:

```text
6leqBaPKPDqaB2l5wefLF6EJV3tr+9+xDvmqWa3CsSdjLWYFt9w57mep0NamM52Y93DOrwkERtBkb+BGCaRa3w==
```

## Hasil

Token hasil forge diterima sebagai akun admin:

```json
{
  "flag": "LYKNCTF{424b7d98da72494bb08e2645eb435e92}",
  "message": "Migration successful. Welcome back, Admin.",
  "profile": {
    "role": "admin",
    "user": "gues",
    "v": "1.0"
  }
}
```

## Flag

```text
LYKNCTF{424b7d98da72494bb08e2645eb435e92}
```
