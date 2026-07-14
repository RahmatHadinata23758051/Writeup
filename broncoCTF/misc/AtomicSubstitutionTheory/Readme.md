# Atomic Substitution Theory

- **CTF:** BroncoCTF
- **Category:** Misc
- **Difficulty:** Easy
- **Flag:** `bronco{my_favorite_messages_have_an_element_of_surprise}`

## File

`secret.txt` hanya berisi rangkaian tuple:

```text
(4, 17), (2, 16), (2, 15), (4, 9), { , ...
```

Judul, deskripsi, dan bentuk koordinatnya mengarah ke tabel periodik.

## Pola Encoding

Dua angka pertama menunjukkan posisi unsur:

```text
(period, group)
```

Tuple dua angka menghasilkan simbol unsur penuh.

Contoh prefix:

| Token | Unsur | Simbol |
|---|---|---|
| `(4, 17)` | Bromine | `Br` |
| `(2, 16)` | Oxygen | `O` |
| `(2, 15)` | Nitrogen | `N` |
| `(4, 9)` | Cobalt | `Co` |

Jika digabung:

```text
Br + O + N + Co = BrONCo
```

Hint meminta semua huruf dalam flag menggunakan lowercase, sehingga prefix-nya menjadi:

```text
bronco{
```

Tuple tiga angka memakai format:

```text
(period, group, character_index)
```

Angka ketiga memilih karakter dari simbol unsur dengan indeks mulai dari 1.

Contoh:

| Token | Simbol | Hasil |
|---|---|---|
| `(3, 2, 1)` | `Mg` | `M` |
| `(4, 17, 2)` | `Br` | `r` |
| `(2, 1, 2)` | `Li` | `i` |
| `(4, 4, 1)` | `Ti` | `T` |
| `(2, 2, 2)` | `Be` | `e` |

Karakter `{`, `}`, dan `_` tidak perlu diubah.

## Decode Bertahap

Bagian awal plaintext:

```text
(3, 2, 1), (5, 3)
Mg[1] + Y
M + Y
my
```

Bagian berikutnya menghasilkan:

```text
favorite
messages
have
element
of
```

Koordinat `(9, 6)` menunjuk Uranium (`U`). Baris 9 dipakai untuk deret aktinida yang biasa ditampilkan terpisah di bawah tabel periodik.

Decoder literal menghasilkan:

```text
bronco{my_favorite_messages_have_at_element_of_suprise}
```

Ada dua inkonsistensi pada ciphertext:

```text
have_at_element  -> have_an_element
suprise          -> surprise
```

Keduanya bukan hasil asumsi flag acak. Kalimat yang terbentuk jelas mengarah ke frasa:

```text
my favorite messages have an element of surprise
```

Versi tersebut juga yang diterima oleh checker.

## Solver

`solve.py` menampilkan hasil decode literal dan flag final setelah dua koreksi plaintext tadi.

```bash
python3 solve.py secret.txt
```

Output:

```text
[raw]   bronco{my_favorite_messages_have_at_element_of_suprise}
[final] bronco{my_favorite_messages_have_an_element_of_surprise}
```

## Flag

```text
bronco{my_favorite_messages_have_an_element_of_surprise}
```
