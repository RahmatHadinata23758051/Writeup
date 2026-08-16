```markdown
# scriptCTF 2026 — OSINT Writeup

## Promotion

### Challenge

> **Promotion**
>
> We have many ways of promoting our event! Can you find a few?

### Goal

Mencari beberapa media atau platform yang digunakan untuk mempromosikan scriptCTF 2026 dan menggabungkan potongan flag yang disembunyikan di masing-masing tempat.

---

## 1. Recon

Homepage event menampilkan bagian:

    Welcome to scriptCTF 2026!

    Our Socials:
    X
    Discord

Challenge menyebutkan **many ways of promoting our event**, sehingga clue mengarah ke beberapa kanal promosi berbeda, bukan hanya satu akun.

Setelah menelusuri beberapa platform yang berkaitan dengan scriptCTF, ditemukan beberapa fragment flag.

---

## 2. Fragment 1 — Discord

Pada Discord resmi scriptCTF ditemukan fragment pertama:

    scriptCTF{w3_

Ini merupakan awal dari flag.

---

## 3. Fragment 2 — Prizes Page

Pada halaman prizes:

    https://ctf.scriptsorcerers.xyz/prizes

ditemukan fragment:

    l0v3

Jika digabungkan dengan fragment sebelumnya:

    scriptCTF{w3_l0v3

---

## 4. Fragment 3 — CTFtime

Pada halaman scriptCTF di CTFtime ditemukan fragment:

    _7h15

Sehingga sementara menjadi:

    scriptCTF{w3_l0v3_7h15

---

## 5. Fragment 4 — X / Twitter

Pada akun X resmi scriptCTF terdapat post promosi yang menyembunyikan fragment terakhir:

    _3v3nt}

---

## 6. Reconstructing the Flag

Semua fragment kemudian digabungkan sesuai urutan:

    Discord : scriptCTF{w3_
    Prizes  : l0v3
    CTFtime : _7h15
    X       : _3v3nt}

Hasil akhirnya:

    scriptCTF{w3_l0v3_7h15_3v3nt}

Jika dibaca menggunakan leetspeak:

    w3      → we
    l0v3    → love
    7h15    → this
    3v3nt   → event

Sehingga pesan tersebut dapat dibaca sebagai:

    we love this event

---

## Flag

    scriptCTF{w3_l0v3_7h15_3v3nt}
```
