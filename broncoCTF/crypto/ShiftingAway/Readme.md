# Shifting Away

## Ringkasan

Cipher yang dipakai adalah **progressive Caesar shift**. Besar pergeseran berubah untuk setiap posisi karakter:

- karakter pada indeks `0` digeser maju `0`
- karakter pada indeks `1` digeser maju `1`
- karakter pada indeks `2` digeser maju `2`
- dan seterusnya

Brace dan underscore tidak ikut diubah, tetapi tetap dihitung sebagai posisi dalam aliran shift.

## Ciphertext

```text
bqmkyj{Ldfmam_Nfd_Abxjpb_Thhdqeia_Snqn_Vzey_Bok_TdudakQkwfy_Kkhxbte_Yo_Jnfvdeueqq}
```

## Analisis

Prefix ciphertext adalah:

```text
bqmkyj
```

Format flag Bronco memakai prefix `bronco`. Perbandingannya langsung membentuk pola:

```text
b + 0 = b
q + 1 = r
m + 2 = o
k + 3 = n
y + 4 = c
j + 5 = o
```

Ini cocok dengan petunjuk `char after char` dan `braces/underscores against the stream`.

Kesalahan yang mudah terjadi adalah menaikkan counter hanya ketika bertemu huruf. Hasilnya tetap acak. Counter yang benar berasal dari **indeks absolut seluruh string**, termasuk `{`, `}`, dan `_`.

## Solver

```python
def decrypt(ciphertext: str) -> str:
    output = []

    for position, char in enumerate(ciphertext):
        if "a" <= char <= "z":
            base = ord("a")
            output.append(chr((ord(char) - base + position) % 26 + base))
        elif "A" <= char <= "Z":
            base = ord("A")
            output.append(chr((ord(char) - base + position) % 26 + base))
        else:
            output.append(char)

    return "".join(output)
```

Jalankan:

```bash
python3 solve.py
```

Output:

```text
<FLAG>bronco{Slowly_But_Surely_Shifting_Away_Into_The_PascalSnake_Strings_Of_Characters}</FLAG>
```

## Flag

```text
bronco{Slowly_But_Surely_Shifting_Away_Into_The_PascalSnake_Strings_Of_Characters}
```
