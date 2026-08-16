# VSS

## Ringkasan

Binary `chal` menjalankan "very security shell". Saat start, program membuat password 16 karakter dari `/dev/urandom`, lalu meminta input user. Kalau input dianggap benar, program menjalankan `/bin/sh`.

Bug-nya ada di validasi password. Program tidak membandingkan input dengan 16 karakter password penuh, tapi memakai panjang input user:

```c
strncmp(input, password, strlen(input))
```

Akibatnya, input 1 karakter akan diterima kalau karakter itu sama dengan karakter pertama password. Karena program mengulang prompt saat salah dan password tidak digenerate ulang selama koneksi yang sama, kita bisa brute force 94 printable character dalam satu koneksi.

## File Challenge

Isi ZIP:

```
Dockerfile
flag.txt
chal
docker-compose.yml
```

`chal` adalah ELF 64-bit PIE stripped. Proteksi stack canary aktif, tetapi tidak perlu bypass karena bug-nya logic bug, bukan overflow.

## Analisis Awal

String penting dari binary:

```
/dev/urandom
Welcome to very security shell
please input your password:
%16s
Wrong password.
You input the right password, welcome!
/bin/sh
```

Program membaca 16 byte dari `/dev/urandom`, lalu setiap byte dimapping ke alphabet printable ASCII non-space.

## Analisis Static

Fungsi generator password:

- buka `/dev/urandom`
- baca 16 byte
- tiap byte dimodulo `0x5e` atau 94
- hasilnya dipakai sebagai indeks alphabet printable
- password diberi null terminator di byte ke-17

Fungsi main:

```c
scanf("%16s", input);
len = strlen(input);
if (len <= 0) wrong;
if (strncmp(input, password, len) == 0) {
    puts("You input the right password, welcome!");
    system("/bin/sh");
}
```

Kesalahan ada pada argumen ketiga `strncmp`. Seharusnya program membandingkan 16 byte penuh atau memakai `strcmp` setelah memastikan panjang input tepat 16.

## Analisis Dynamic

Test lokal menunjukkan cukup brute force 1 karakter. Saat salah, program mencetak `Wrong password.` dan kembali meminta password yang sama. Saat benar, program spawn `/bin/sh`.

## Algoritma Exploit

1. Connect ke service.
2. Baca banner sampai prompt password.
3. Kirim semua karakter alphabet satu per satu:

```
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
```

4. Kalau output mengandung `right password`, shell sudah aktif.
5. Kirim command, default:

```
cat flag.txt; cat /flag 2>/dev/null
```

## Cara Menjalankan

Remote:

```bash
python3 solve.py
```

Output:

```
You input the right password, welcome!
[+] matched first password character: '&'
THJCC{strnc0mp_1s_n0t_s3cur3}
```

## Flag

```
THJCC{strnc0mp_1s_n0t_s3cur3}
```
