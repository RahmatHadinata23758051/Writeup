# Silent

## Ringkasan

Challenge ini menjalankan `eval` dengan `__builtins__` kosong. Input harus berupa list, setiap elemen maksimal 13 karakter, dan seluruh karakter elemen harus berasal dari whitelist:

```text
),dw.r_[silent]g=c:f(
```

Escape dilakukan dengan walrus assignment, attribute lookup, dan pemanggilan method yang dibangun dari panjang list.

## File Challenge

- `main.py`: validator dan evaluator input.
- `Dockerfile`: image Python challenge.
- `entrypoint.sh`: membuat `/flag-<random>.txt` lalu menjalankan service.
- `solve.py`: generator payload, tracer lokal, dan transport `ncat --ssl`.

## Analisis Awal

Objek Python dapat diperoleh dari `[]`, lalu `object.__subclasses__()` diakses tanpa literal nama. Dari daftar subclass, `os._wrap_close` memberi akses ke `__init__.__globals__`, yaitu dictionary global module `os`.

Semua integer indeks dibuat dari panjang list sementara. Untuk dictionary, payload membuat iterator baru, mengambil method `__next__` melalui `__dir__`, lalu memanggil `next()` sebanyak indeks yang dibutuhkan.

## Temuan Penting

Pada image lokal `python:3.14.7-slim-trixie`, indeks yang dipakai adalah:

- `os._wrap_close`: subclass index `167`.
- `function.__globals__`: `__dir__` index `5`.
- `dict_keyiterator.__next__`: `__dir__` index `1`.
- `os.__globals__['__builtins__']`: key index `6`.
- `builtins['open']`: key index `152`.
- `builtins['print']`: key index `42`.
- `list.sort`: `__dir__` index `33`.
- file `read`: `__dir__` index `7`.

Instance remote `silent-af99fbbb84c0.chall.nnsc.tf` memiliki `_wrap_close` pada index `166`, sehingga command remote memakai `SUBIDX=166`. Host `silent-77fe515e5473.chall.nnsc.tf` yang dicoba membalas `HTTP/1.1 400 Bad Request` sebelum challenge prompt.

## Proses Ekstraksi

`solve.py` menjalankan tahap berikut:

1. Mendapatkan `object` dan getter attribute dari dictionary class.
2. Mengambil subclass `os._wrap_close`.
3. Mengambil `__init__.__globals__` sebagai dictionary `os`.
4. Mengambil `chdir`, `getcwd`, dan `listdir` dari dictionary tersebut.
5. Mengambil dictionary builtins melalui key `__builtins__`.
6. Mengubah current directory ke `/`, mengambil dan mengurutkan listing root.
7. Memilih entry root pada index `5`, yaitu file flag `flag-*`.
8. Membuka file, mengambil `read` melalui `__dir__`, lalu mengambil `print` melalui iterator builtins baru.
9. Mencetak isi flag.

Setiap akses dictionary memakai iterator baru agar state iterator sebelumnya tidak tertimpa.

## Solve Script

Generator memastikan semua elemen payload memenuhi whitelist dan batas panjang sebelum payload dikirim. Mode `--trace` mengevaluasi elemen satu per satu dan melaporkan index, exception, serta state ringkas jika gagal.

## Cara Menjalankan

Validasi lokal:

```bash
docker run --rm -e SUBIDX=167 \
  -v "$PWD:/work" -w /work python:3.14.7-slim-trixie \
  sh -lc 'printf LOCALFLAG > /flag-test.txt; python3 solve.py --trace'

docker run --rm -e SUBIDX=167 \
  -v "$PWD:/work" -w /work python:3.14.7-slim-trixie \
  sh -lc 'printf LOCALFLAG > /flag-test.txt; python3 solve.py --eval'
```

Remote instance yang berhasil:

```bash
HOST='silent-af99fbbb84c0.chall.nnsc.tf' PORT=1337 SUBIDX=166 python3 solve.py
```

Transport script menggunakan `ncat --ssl --no-shutdown`.

## Flag

```text
<FLAG>NNS{Y0UR_loUDN355_is_De4Fen1ng}</FLAG>
```

## Catatan

Kegagalan payload sebelumnya berasal dari getter `g` yang tertimpa oleh builtin lain, key iterator yang digunakan ulang setelah state scratch tertimpa, serta perbedaan urutan `object.__subclasses__()` antara image lokal dan instance remote. Generator final memisahkan state dictionary dan selalu membuat iterator baru.
