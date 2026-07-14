# Blorg Multiplier

## Ringkasan

Service memvalidasi command memakai:

```python
select = hashlib.md5(bytes_in).hexdigest()

if select not in valid:
    print("That is not a real command!")
    return
```

Ada dua masalah yang bisa digabung:

1. Command `show` praktis tidak bisa dipakai karena hash yang disimpan di `valid` berbentuk uppercase, sedangkan `hexdigest()` selalu lowercase.
2. Command `program` membolehkan user menambahkan hash MD5 command baru ke whitelist.

Solusinya memakai **dua input berbeda dengan hash MD5 yang sama**:

```text
MD5(collision_A) == MD5(collision_B)
collision_A != collision_B
```

`collision_A` didaftarkan sebagai nama custom program. Setelah jumlah blorg tepat `468`, `collision_B` dikirim. Hash-nya lolos whitelist, tetapi string-nya tidak sama dengan nama program, sehingga masuk ke branch `else` yang mencetak flag.

## Source yang relevan

```python
elif user_in == "program":
    if program is not None:
        valid.remove(hashlib.md5(program.encode("latin-1")).hexdigest())

    program = input("What is the name of the new command? ")
    program_cmd = input(
        "Which (space separated) commands would you like it to run:"
    )

    valid.add(hashlib.md5(program.encode("latin-1")).hexdigest())
```

Branch flag:

```python
elif user_in == program:
    for cmd in program_cmd.split(" "):
        handle_input(cmd.encode("latin-1"))
else:
    if blorgs == TARGET:
        print(f"Wow! You earned the flag: {FLAG}")
```

Collision kedua harus:

- memiliki MD5 yang sama agar lolos `valid`
- berbeda secara byte/string agar tidak masuk ke `user_in == program`

## Mengatur blorg menjadi 468

Nilai awal:

```text
blorgs = 1
MAX_EDITS = 3
```

Perintah:

```python
increase: (blorgs + 1) * 2
decrease: (blorgs - 1) * 2
none: blorgs * 2
```

Gunakan urutan:

```text
none
none
none
none
decrease
none
decrease
decrease
none
```

Perubahannya:

```text
1
-> 2       none
-> 4       none
-> 8       none
-> 16      none
-> 30      decrease, edit 1
-> 60      none
-> 118     decrease, edit 2
-> 234     decrease, edit 3
-> 468     none
```

Jumlah edit tepat tiga.

Loop masih berjalan saat `blorgs == 468` karena kondisinya memakai `<=`:

```python
while blorgs <= TARGET and edits <= MAX_EDITS:
```

## MD5 collision

Solver memakai collision pair MD5 klasik berukuran 128 byte. Keduanya memiliki digest:

```text
79054025255fb1a26e4bc422aef54eb4
```

Validasi lokal:

```python
assert collision_a != collision_b
assert hashlib.md5(collision_a).digest() == hashlib.md5(collision_b).digest()
```

## Masalah encoding remote

Payload collision mengandung byte non-ASCII. Service membaca input sebagai string, lalu mengubahnya kembali dengan Latin-1:

```python
user_in = bytes_in.decode("latin-1")
```

Saat mendaftarkan program:

```python
program.encode("latin-1")
```

Agar byte mentah collision tetap sama setelah melewati terminal UTF-8:

```python
wire = raw.decode("latin-1").encode("utf-8")
```

Urutannya:

```text
raw collision bytes
-> decode latin-1 menjadi Unicode
-> encode UTF-8 untuk dikirim
-> input() membaca Unicode yang sama
-> encode latin-1 di server
-> kembali menjadi raw collision bytes
```

## Solver

Dependency:

```bash
python3 -m pip install pwntools
```

Jalankan:

```bash
python3 solve.py 0.cloud.chals.io 13758
```

Alur solver:

1. Validasi collision pair.
2. Kirim `program`.
3. Daftarkan `collision_A` sebagai nama command.
4. Jalankan sequence sampai blorg menjadi `468`.
5. Kirim `collision_B`.
6. Ambil flag dari response.

Output:

```text
<FLAG>bronco{ple4s3_d0nt_l3ak_fl4g}</FLAG>
```

## Flag

```text
bronco{ple4s3_d0nt_l3ak_fl4g}
```
