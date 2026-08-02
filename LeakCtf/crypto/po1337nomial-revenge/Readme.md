# Writeup CTF: po1337nomial-revenge

## Deskripsi Challenge

Challenge ini merupakan versi *revenge* dari challenge `po1337nomial` Crew CTF 2025. Pada versi original, server membuat 1337 koefisien polynomial dari output Python `random.getrandbits(32)`, kemudian memberikan tiga menu utama: mengambil koefisien yang sudah diacak, mengevaluasi polynomial, dan membuka flag. Pada writeup original, option `Evaluate` masih mencetak nilai polynomial `y` sehingga nilai tersebut dapat digunakan untuk mengembalikan urutan koefisien.

Pada versi revenge, bagian `Evaluate` sudah diubah menjadi:

```python id="p5mqwm"
if option == '2':
    x = int(input('x: '))
    a[randrange(0, 1337)] = 1337
    print('y:', 'REDACTED')
```

Artinya nilai polynomial tidak lagi bocor. Oleh karena itu, teknik original yang melakukan *backtracking* dari nilai `y` tidak dapat digunakan lagi. Pada writeup original, langkah tersebut memang bergantung pada pengambilan nilai `y` dari server.

Flag yang diperoleh:

```text id="7hj3ul"
L3AK{19937_bottles_of_beer_on_the_wall}
```

## Analisis Source Code

Source challenge:

```python id="wucot6"
from os import getenv
from random import getrandbits, randbytes, randrange, shuffle

FLAG = getenv('FLAG', 'L3AK{fake_flag}')

a = [getrandbits(32) for _ in range(1337)]
options = {'1': 'Get coefficients', '2': 'Evaluate', '3': 'Unlock flag'}

while options:
    option = input(''.join(f'\n{k}. {v}' for k, v in options.items()) + '\n> ')

    if option not in options:
        break

    options.pop(option)

    if option == '1':
        shuffle(s := a.copy())
        print('s:', s)

    if option == '2':
        x = int(input('x: '))
        a[randrange(0, 1337)] = 1337
        print('y:', 'REDACTED')

    if option == '3':
        if input('k: ') == randbytes(1337).hex():
            print(FLAG)
```

Ada beberapa poin penting:

1. List `a` berisi 1337 output dari `getrandbits(32)`.
2. Python `random` menggunakan MT19937.
3. Option `1` memberikan semua elemen `a`, tetapi sudah diacak menggunakan `shuffle`.
4. Option `2` tidak berguna karena output `y` sudah `REDACTED`.
5. Untuk mendapatkan flag, kita harus memprediksi output berikutnya dari `randbytes(1337)`.

Pada writeup original juga dijelaskan bahwa Python `random` menggunakan MT19937 dan state-nya dapat dipulihkan jika kita memiliki cukup output 32-bit.

## Perbedaan dengan Challenge Original

Pada challenge original, solusi menggunakan dua informasi:

```text id="bvf0qb"
1. Shuffled coefficients dari option 1
2. Nilai y dari option 2
```

Nilai `y` dipakai untuk mengembalikan urutan koefisien polynomial. Setelah urutan koefisien asli ditemukan, state MT19937 dapat direkonstruksi, kemudian `shuffle` dan `randbytes` dapat diprediksi. Di writeup original, setelah urutan koefisien ditemukan, state MT19937 direkonstruksi lalu digunakan untuk memprediksi `randbytes(1337)`.

Namun pada versi revenge, `y` tidak diberikan. Jadi solusi harus langsung menyusun ulang output MT19937 dari list yang sudah diacak.

## Ide Penyelesaian

Walaupun option `1` hanya memberikan list acak, semua elemennya tetap berasal dari output berurutan MT19937:

```text id="b95rln"
a[0], a[1], a[2], ..., a[1336]
```

Setiap nilai tersebut adalah output hasil *tempering* dari internal state MT19937. Kita bisa melakukan *untemper* terhadap setiap output untuk mendapatkan nilai internal state mentah.

Setelah di-*untemper*, kita punya 1337 nilai state, tetapi posisinya masih acak.

MT19937 memiliki relasi linear antar-state. Untuk urutan internal state `u`, berlaku relasi:

```text id="ihjx7a"
u[i + 624] = u[i + 397] ^ twist(u[i], u[i + 1])
```

Dengan kata lain, dari pasangan nilai tertentu pada posisi `i + 397` dan `i + 624`, kita bisa mendapat informasi tentang nilai pada posisi `i`.

Karena kita memiliki 1337 nilai, relasi ini cukup untuk menyusun ulang urutan output asli dari list yang sudah diacak.

## Strategi Exploit

Langkah exploit:

1. Ambil shuffled coefficients dari option `1`.
2. Lakukan `untemper` pada semua nilai.
3. Cari relasi MT19937 antar nilai internal state.
4. Gunakan constraint solving sederhana untuk menentukan posisi asli setiap nilai.
5. Setelah urutan asli ditemukan, clone state Python `random`.
6. Simulasikan `shuffle` agar state lokal sama dengan state server setelah option `1`.
7. Prediksi `randbytes(1337)`.
8. Kirim hasilnya ke option `3`.

Kita tidak menggunakan option `2` sama sekali, karena selain `y` sudah `REDACTED`, option tersebut juga mengubah satu koefisien dengan `1337` dan mengonsumsi random melalui `randrange`.

## Solver

```python id="v1ud41"
#!/usr/bin/env python3
from pwn import remote, context
import ast
import random
from collections import defaultdict

context.log_level = "info"

HOST = "po1337nomial-revenge.instances.ctf.l3ak.team"
PORT = 1337

N = 1337
MASK = 0xffffffff
MATRIX_A = 0x9908b0df
LOW30 = (1 << 30) - 1


def temper(y):
    y &= MASK
    y ^= y >> 11
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= y >> 18
    return y & MASK


def undo_right(y, shift):
    x = y
    for _ in range(6):
        x = y ^ (x >> shift)
    return x & MASK


def undo_left(y, shift, mask):
    x = y
    for _ in range(6):
        x = y ^ ((x << shift) & mask)
    return x & MASK


def untemper(y):
    y = undo_right(y, 18)
    y = undo_left(y, 15, 0xefc60000)
    y = undo_left(y, 7, 0x9d2c5680)
    y = undo_right(y, 11)
    return y & MASK


def candidate_labels(a, b, valset):
    t = a ^ b
    out = []

    for parity in (0, 1):
        v = t ^ (MATRIX_A if parity else 0)

        if v & 0x80000000:
            continue

        low31 = ((v & LOW30) << 1) | parity

        for cand in (low31, low31 | 0x80000000):
            if cand in valset:
                out.append(cand)

    return out


def extract_relations(states):
    vals = list(states)
    valset = set(vals)
    rels = []

    for i, a in enumerate(vals):
        for b in vals[i + 1:]:
            for lab in candidate_labels(a, b, valset):
                rels.append((lab, a, b))

    return rels


def ac_step(domains, rels):
    changed = False

    for lab, a, b in rels:
        dl = domains[lab]
        da = domains[a]
        db = domains[b]

        nl, na, nb = set(), set(), set()

        for pos in dl:
            p1 = pos + 396
            p2 = pos + 623

            if p1 in da and p2 in db:
                nl.add(pos)
                na.add(p1)
                nb.add(p2)

            if p2 in da and p1 in db:
                nl.add(pos)
                na.add(p2)
                nb.add(p1)

        if not nl or not na or not nb:
            return False, False

        if nl != dl:
            domains[lab] = nl
            changed = True
        if na != da:
            domains[a] = na
            changed = True
        if nb != db:
            domains[b] = nb
            changed = True

    return changed, True


def alldiff_step(domains):
    changed = False

    fixed = {}
    for v, d in domains.items():
        if len(d) == 1:
            idx = next(iter(d))
            if idx in fixed and fixed[idx] != v:
                return False, False
            fixed[idx] = v

    for idx, v in fixed.items():
        for w, d in domains.items():
            if w != v and idx in d:
                d.remove(idx)
                changed = True
                if not d:
                    return False, False

    inv = defaultdict(list)
    for v, d in domains.items():
        for idx in d:
            inv[idx].append(v)

    for idx, vs in inv.items():
        if len(vs) == 1:
            v = vs[0]
            if len(domains[v]) > 1:
                domains[v] = {idx}
                changed = True

    return changed, True


def solve_relations(rels):
    nodes = set()
    for lab, a, b in rels:
        nodes.add(lab)
        nodes.add(a)
        nodes.add(b)

    if len(nodes) != N:
        raise RuntimeError(f"nodes={len(nodes)}, expected {N}")

    domains = {v: set(range(N)) for v in nodes}

    label_range = set(range(0, 714))
    endpoint_range = set(range(396, N))

    for lab, a, b in rels:
        domains[lab] &= label_range
        domains[a] &= endpoint_range
        domains[b] &= endpoint_range

    for _ in range(200):
        c1, ok = ac_step(domains, rels)
        if not ok:
            return None

        c2, ok = alldiff_step(domains)
        if not ok:
            return None

        if not c1 and not c2:
            break

    if not all(len(d) == 1 for d in domains.values()):
        return None

    pos = {v: next(iter(d)) for v, d in domains.items()}

    if len(set(pos.values())) != N:
        return None

    for lab, a, b in rels:
        lp = pos[lab]
        if sorted((pos[a], pos[b])) != [lp + 396, lp + 623]:
            return None

    seq = [None] * N
    for v, p in pos.items():
        seq[p] = v

    if any(x is None for x in seq):
        return None

    return seq


def recover_state_sequence(shuffled_coeffs):
    if len(set(shuffled_coeffs)) != len(shuffled_coeffs):
        raise RuntimeError("duplicate 32-bit output, reconnect")

    states = [untemper(x) for x in shuffled_coeffs]
    rels = extract_relations(states)

    print(f"[*] extracted relations: {len(rels)}")

    if len(rels) != 714:
        raise RuntimeError(f"relations={len(rels)}, expected 714; reconnect")

    seq = solve_relations(rels)
    if seq is None:
        raise RuntimeError("constraint solve failed; reconnect")

    return seq


def solve_once():
    io = remote(HOST, PORT, ssl=True)

    io.sendlineafter(b"> ", b"1")
    io.recvuntil(b"s: ")

    shuffled_coeffs = ast.literal_eval(io.recvline().decode())
    print("[+] got shuffled coefficients")

    state_seq = recover_state_sequence(shuffled_coeffs)
    coeff_seq = [temper(x) for x in state_seq]

    print("[+] recovered original MT output order")

    rng = random.Random()
    rng.setstate((3, tuple(state_seq[624:1248]) + (624,), None))

    for i in range(1248, 1337):
        got = rng.getrandbits(32)
        assert got == coeff_seq[i], f"MT sync failed at {i}"

    print("[+] synced RNG after coefficient generation")

    test = coeff_seq.copy()
    rng.shuffle(test)

    if test != shuffled_coeffs:
        raise RuntimeError("shuffle verification failed; reconnect")

    print("[+] shuffle verified, RNG synced before option 3")

    k = rng.randbytes(1337).hex()

    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"k: ", k.encode())

    print(io.recvall(timeout=5).decode(errors="ignore"))


def main():
    while True:
        try:
            solve_once()
            break
        except Exception as e:
            print("[!] failed:", e)
            print("[*] reconnecting...")


if __name__ == "__main__":
    main()
```

## Menjalankan Solver

Install dependency:

```bash id="zqmpxw"
pip install pwntools
```

Jalankan:

```bash id="e55jqc"
python3 solve.py
```

Contoh hasil:

```text id="fo90tg"
[+] Opening connection to po1337nomial-revenge.instances.ctf.l3ak.team on port 1337: Done
[+] got shuffled coefficients
[*] extracted relations: 714
[+] recovered original MT output order
[+] synced RNG after coefficient generation
[+] shuffle verified, RNG synced before option 3
L3AK{19937_bottles_of_beer_on_the_wall}
```

## Kesimpulan

Challenge ini mengeksploitasi fakta bahwa 1337 koefisien berasal langsung dari output MT19937. Walaupun koefisien diberikan dalam urutan acak dan nilai evaluasi polynomial sudah disembunyikan, recurrence internal MT19937 masih cukup kuat untuk menyusun kembali urutan output.

Setelah urutan asli 1337 output ditemukan, state Python `random` dapat disinkronkan kembali. Kita cukup mensimulasikan `shuffle` yang dilakukan option `1`, lalu memprediksi nilai `randbytes(1337)` untuk membuka flag.

Flag:

```text id="8ixpnr"
L3AK{19937_bottles_of_beer_on_the_wall}
```
