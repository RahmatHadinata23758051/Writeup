# rev/remoose

Challenge ini ternyata bukan binary ELF biasa yang tinggal dijalankan. Dari hasil `file chall`, file malah terbaca sebagai `data`, dan `readelf` juga langsung nolak karena magic bytes-nya salah.

## Temuan awal

Header file dimulai dengan:

```text
7f 45 4c 4b
```

Harusnya ELF memakai:

```text
7f 45 4c 46
```

Jadi byte keempat sengaja diubah dari `F` menjadi `K`.

Setelah dicek lebih jauh, ada hal yang lebih penting: file ini sama sekali tidak punya byte `0x00`. Sebagai gantinya, hampir seluruh posisi yang semestinya nol berubah menjadi `0x20` atau spasi. Ini kelihatan jelas dari ELF header, karena field-field seperti `e_type`, `e_machine`, `e_entry`, `e_phoff`, dan lain-lain punya pola yang masuk akal kalau `0x20` dibaca sebagai `0x00`.

Contoh sederhana:

```text
03 20 -> 03 00
3e 20 -> 3e 00
60 10 20 20 20 20 20 20 -> 60 10 00 00 00 00 00 00
```

Artinya challenge ini dirusak dengan cara mengganti byte nol menjadi spasi, lalu satu byte magic ELF juga diubah.

## Rekonstruksi dan reversing

Saya buat salinan kerja dan memulihkan dua hal berikut:

1. Semua `0x20` saya anggap `0x00` untuk kebutuhan parsing struktur ELF.
2. Byte magic `K` saya balikin ke `F`.

Hasilnya cukup untuk membaca symbol table. Dari sana muncul fungsi-fungsi penting:

- `main` di `0x1145`
- `flag` di `0x117f`
- `flag1` di `0x11c9`
- `flag2` di `0x1229`
- `flag3` di `0x115a`
- `flag4` di `0x11ee`

Lalu saya dump `.text` sebagai raw binary dan disassemble dengan `objdump -b binary -m i386:x86-64`.

Alur `main` sangat pendek:

```c
main() {
    flag();
    return 1;
}
```

Fungsi `flag` dan turunannya mencetak karakter satu per satu lewat `putchar`, lalu sedikit memakai `printf`.

## Susunan karakter

### `flag`

Mencetak:

- `t`
- `j`
- `c`
- `t`

Lalu memanggil `printf` dengan string di `0x2004`. Dari konteks pemanggilan, string ini harus menjadi `f{`, karena kalau spasi di tengah dianggap literal maka `printf` akan mencoba membaca argumen `%c` yang tidak pernah dikirim.

Jadi awal flag:

```text
tjctf{
```

### `flag1`

Mencetak:

```text
5m
```

### `flag2`

Mencetak:

```text
a11_
```

### `flag3`

Mencetak:

```text
m0
```

### `flag4`

Di sini ada jebakan kecil. Kalau semua `0x20` dibabi-buta diubah jadi `0x00`, salah satu instruksi `call` jadi terlihat menuju alamat `0x1010`, padahal aslinya rel32 call itu masih memakai byte `0x20` yang valid sebagai bagian offset.

Dari byte asli:

```text
e8 20 fe ff ff
```

offset ini sebenarnya mengarah ke `putchar@plt`, jadi fungsi `flag4` mencetak:

```text
0
s
3
```

Lalu `printf("%c\\r", '}')` untuk menutup kurung kurawal.

## Flag akhir

Jika semua potongan digabung:

```text
tjctf{5ma11_m00s3}
```

## Catatan

Inti challenge ini bukan eksploit memory corruption, tapi mengenali bahwa binary sengaja dirusak dengan substitusi `NUL -> space` dan satu byte magic ELF diubah supaya tool standar gagal membacanya secara langsung. Setelah itu, symbol table dan disassembly sudah cukup untuk menyusun flag tanpa perlu menjalankan binary aslinya.
