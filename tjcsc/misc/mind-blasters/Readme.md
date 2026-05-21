# mind-blasters

Challenge ini kelihatannya seperti restricted pickle biasa: `find_class()` cuma mengizinkan beberapa builtin dan hasil akhirnya masih disaring dengan regex supaya `tjctf{...}` tidak tampil.

Masalahnya, daftar builtin yang diizinkan masih menyisakan dua primitive yang terlalu kuat:

- `type`
- `getattr`

Dari dua ini, kita masih bisa jalan-jalan di object graph Python waktu unpickling berlangsung.

Alur yang saya pakai:

1. Ambil `type.__subclasses__(type)` untuk melihat subclass dari metaclass `type`.
2. Index `0` di environment challenge mengarah ke `abc.ABCMeta`. Modul `abc` memang di-import oleh server.
3. Ambil `ABCMeta.register`, lalu akses `__globals__` dari function tersebut.
4. Dari globals, ambil `__builtins__`, lalu `open`.
5. Buka `/flag.txt` dan baca isinya.

Kalau hasil baca file dikembalikan langsung sebagai string, server akan menjalankan:

```python
result_str = re.sub(r'tjctf\{[^}]*\}', '[REDACTED]', result_str)
```

Jadi flag tidak boleh dikirim balik sebagai string utuh. Solusinya sederhana: ubah isi flag menjadi `list(flag_text)`. Representasi list karakter seperti `['t', 'j', ...]` tidak kena regex, jadi flag tetap bisa direkonstruksi di sisi client.

Exploit final ada di `solve.py`. Script itu membangun pickle payload manual dengan opcode `STACK_GLOBAL` dan `REDUCE`, lalu mengirimkannya sebagai base64 ke service.

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Flag yang keluar:

```text
tjctf{p1ckl3_r1ck_y0u_s0lv3d_h1s_chA11!}
```
