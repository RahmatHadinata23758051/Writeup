# glyphs — Write-up

## Ringkasan

Binary `glyphs` tidak melakukan pengecekan flag dengan `strcmp` biasa. Program menjalankan interpreter glyph 2D yang pada akhirnya membangun term **lambda-calculus**.

Input yang benar membuat term final mengevaluasi cabang `good`, sedangkan input yang salah mengevaluasi cabang `nope`.

### Flag

```text
uiuctf{oRig1naLLy_7His_W4s_gonna_be_moR3_FoCU53d_0N_the_G4M3s_p4rt_BU7_1_f3ll_d0WN_7h3_l4mbD4_c4lc_R4bb17_H0Le_50_HeR3_w3_4r3_noW_41n7_7H47_gR3at}
```

---

## File Challenge

```bash
$ file glyphs
glyphs: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

Binary berupa ELF 64-bit PIE yang stripped dan berukuran cukup besar.

String plaintext flag juga tidak muncul pada `strings`, dan output program hanya berupa:

```text
good
```

atau:

```text
nope
```

---

## Analisis Awal

Program menerima flag melalui `argv`:

```bash
$ ./glyphs test
nope
```

Output `good` dan `nope` disimpan sebagai konstanta integer kecil:

```text
good = 0x646f6f67
nope = 0x65706f6e
```

Jalur utama berada di sekitar fungsi `main`, kemudian masuk ke interpreter yang cukup besar.

Dari trace, ekspresi final yang dievaluasi memiliki bentuk:

```text
((((((Y) checker) target_term) input_term) nope) good)
```

Secara konseptual:

```text
Y checker target input nope good
```

`checker` akan memilih `good` hanya jika struktur `input_term` cocok dengan `target_term`.

---

## Analisis Static

Disassembly menunjukkan beberapa bagian penting:

- Fungsi utama memanggil interpreter dengan input dari `argv`.
- Interpreter berjalan di atas grid glyph 2D yang berada pada section data.
- Hasil akhirnya bukan string, melainkan pointer ke struktur node lambda-calculus.
- Check final dilakukan sebelum program memilih cabang `good` atau `nope`.

Karena binary merupakan PIE, breakpoint dipasang relatif terhadap base address.

Titik yang digunakan untuk melakukan dump term final berada di sekitar:

```text
base + 0x4375
```

Pada titik tersebut, argumen final dapat dibaca sebelum evaluasi check selesai.

---

## Analisis Dynamic

Dengan menggunakan `ptrace`/GDB, root term final didump dan kemudian diparse sebagai AST lambda-calculus.

Target term dan input term berada sebagai argumen pada bentuk:

```text
Y checker target input nope good
```

Evaluator lambda lokal dibuat untuk memastikan hipotesis tersebut.

Ketika:

```text
input_term = target_term
```

evaluator memilih:

```text
good
```

Sedangkan ketika menggunakan input biasa, hasilnya:

```text
nope
```

Jadi tantangan utamanya adalah mendapatkan struktur input yang menghasilkan term yang ekuivalen dengan `target_term`.

---

## Struktur Input

Input ternyata tidak diproses secara sederhana dari kiri ke kanan.

Program membentuk block dari karakter input dengan pola:

1. Block pertama adalah karakter terakhir.
2. Block berikutnya adalah pasangan dua karakter dari belakang menuju depan.
3. Untuk panjang genap, karakter paling awal tidak ikut dibandingkan secara langsung.

Contoh:

```text
abc
```

menjadi:

```text
c, ab
```

Sedangkan:

```text
abcd
```

menjadi:

```text
d, bc
```

Pada kasus `abcd`, karakter `a` menjadi byte awal yang tidak dicek secara langsung.

---

## Jumlah Block

Jumlah block yang cocok dengan target adalah:

```text
73 block
```

Sehingga panjang flag yang digunakan adalah:

```text
73 × 2 = 146 karakter
```

Walaupun terdapat beberapa posisi yang tidak benar-benar dibaca oleh checker, panjang input tetap harus memenuhi struktur yang diharapkan binary.

---

## Algoritma Validasi / Encoding

Setiap block input diubah menjadi nilai internal berbasis 3, kemudian dikodekan menjadi term lambda.

Target term juga menyimpan block dengan encoding yang sama.

Dari dump target diperoleh:

```text
141 node label
```

Setelah dilakukan kalibrasi menggunakan input acak unik untuk berbagai panjang, panjang yang cocok adalah:

```text
73 block
```

Dari 73 block tersebut, terdapat **58 posisi input** yang benar-benar dibaca oleh checker.

Artinya, tidak semua karakter flag memiliki pengaruh terhadap hasil validasi.

---

## Template Hasil Reverse

Mapping dari block yang dicek menghasilkan template:

```text
uiuctf{oRig1naLLy_7HiAAW4s_gonna_be_moR3_FoCU53d_0N_the_GAAAA_p4rt_BU7_AAf3AA_d0WN_7h3_AAmbD4_c4lc_R4AAAA_H0Le_AA_HAA3_w3AAr3_noW_4AA7_7H47_gAAat}
```

Karakter `A` menandakan posisi yang **tidak dibaca oleh checker**.

Binary menerima byte apa pun pada posisi tersebut selama panjang input dan block yang diperiksa tetap benar.

---

## Mengisi Posisi yang Tidak Dicek

Karena template tersebut sudah cukup jelas membentuk kalimat leetspeak, posisi `A` dapat diisi berdasarkan kalimat:

> originally this was gonna be more focused on the games part but I fell down the lambda calc rabbit hole so here we are now ain't that great

Setelah seluruh posisi kosong diisi, diperoleh flag final:

```text
uiuctf{oRig1naLLy_7His_W4s_gonna_be_moR3_FoCU53d_0N_the_G4M3s_p4rt_BU7_1_f3ll_d0WN_7h3_l4mbD4_c4lc_R4bb17_H0Le_50_HeR3_w3_4r3_noW_41n7_7H47_gR3at}
```

---

## Penyusunan Solve Script

`solve.py` menyimpan template hasil reverse dan mengisi posisi yang tidak dicek dengan karakter yang membentuk kalimat flag utuh.

Script juga melakukan pengecekan format dan panjang:

```python
assert flag.startswith("uiuctf{") and flag.endswith("}")
assert len(flag) == 146
```

Contoh struktur sederhana:

```python
template = "..."

# Isi posisi yang tidak dicek berdasarkan kalimat flag.
flag = template.replace("A", "...")

assert flag.startswith("uiuctf{")
assert flag.endswith("}")
assert len(flag) == 146

print(flag)
```

---

## Cara Menjalankan

Generate flag menggunakan:

```bash
python3 solve.py
```

Kemudian berikan hasilnya ke binary:

```bash
./glyphs "$(python3 solve.py)"
```

Output:

```text
good
```

---

## Flag

```text
uiuctf{oRig1naLLy_7His_W4s_gonna_be_moR3_FoCU53d_0N_the_G4M3s_p4rt_BU7_1_f3ll_d0WN_7h3_l4mbD4_c4lc_R4bb17_H0Le_50_HeR3_w3_4r3_noW_41n7_7H47_gR3at}
```

---

