# find-da-code

Challenge ini ternyata jauh lebih gampang kalau fokus ke pola output-nya, bukan ke urutan pilihannya.

Service menampilkan 4 stage. Setiap stage berisi 10 token heksadesimal dan kita diminta memilih 1 sampai 10. Dari deskripsi awal, saya sempat anggap ini model "ingat 4 kode" biasa, tapi ada satu petunjuk penting: input aneh seperti `0`, `11`, `-1`, bahkan `a` tetap diterima sampai stage terakhir. Saat semua input selesai, service kadang crash dan mengeluarkan traceback Python.

Bagian paling penting dari traceback itu ini:

```python
if sorted(selected_tokens) == sorted(CORRECT_TOKENS):
```

Dari sini kelihatan kalau:

1. Service sebenarnya tidak peduli urutan token.
2. Ada konstanta `CORRECT_TOKENS`.
3. Yang dicek di akhir adalah himpunan 4 token yang kita pilih.

Langkah berikutnya cuma tinggal ngumpulin beberapa sampel layar login dari banyak koneksi. Setelah diamati, ada 4 token yang terus muncul berulang:

- `1A2B`
- `00FA`
- `9C4F`
- `88D1`

Empat token ini selalu hadir, tapi posisi stage-nya acak. Kadang `1A2B` muncul di stage 1, kadang di stage 3, dan seterusnya. Artinya solusi paling bersih adalah:

1. Baca 10 token di setiap stage.
2. Cari mana yang termasuk ke set token benar.
3. Kirim index token itu.
4. Ulangi sampai stage 4.

Setelah empat token tersebut dipilih, service langsung mengembalikan:

```text
ACCESS GRANTED.
tjctf{brut3_f0rc3_th3_t3rm1n4l}
```

Solver final ada di `solve.py`. Script itu membuka koneksi ke service, mem-parse token dengan regex, mencari index dari salah satu token benar di setiap stage, lalu mengirim pilihannya otomatis.
