# Writeup CTF - WhoAmI? Cyber-eto

## Informasi Challenge

- **Judul:** WhoAmI? Cyber-eto
- **Kategori:** OSINT

---

# Ringkasan

Challenge ini mengisahkan seorang developer bernama **Julian AbuTaifeha** yang mengaku salah satu tools buatannya telah dikompromikan. Petunjuk awal mengarahkan peserta untuk menemukan akun Reddit miliknya menggunakan **Initial-Based Username Convention**, kemudian mengikuti jejak digitalnya hingga memperoleh flag.

Secara garis besar alur penyelesaiannya adalah sebagai berikut:

```text
Julian AbuTaifeha
        │
        ▼
Reddit : J_AbuTaifeha
        │
        ▼
GitHub : J-AbuTaifeha
        │
        ├── I-m-Good-at-Cyber-Security-
        │       └── Commit lama mengungkap nama penyerang
        │
        ├── Julian-s-Calculator
        │       └── Commit lama mengungkap petunjuk Telegram Bot
        │
        └── MyFirstProject
                └── Riwayat README membocorkan username bot
                        │
                        ▼
                Telegram Bot
                        │
                        ▼
KaliTeam{1_th1nk_y0u_kn0w_051NT!}
```

---

# Analisis Awal

Challenge memberikan dua petunjuk:

> Use the Initial-Based Username Convention to reach Julian's account.

> *"The one you are looking with is the one you are looking for."*

Dari nama:

```text
Julian AbuTaifeha
```

gunakan inisial nama depan kemudian diikuti nama belakang.

Hasilnya:

```text
J_AbuTaifeha
```

---

# Menemukan Akun Reddit

Username tersebut mengarah ke akun Reddit:

```text
u/J_AbuTaifeha
```

Pada akun tersebut terdapat posting mengenai salah satu tool miliknya yang telah dikompromikan.

Judul posting tersebut mengarahkan peserta untuk menyelidiki repository yang dimiliki Julian.

---

# Menelusuri Repository GitHub

Dengan pola username yang sama, akun GitHub ditemukan menggunakan variasi tanda hubung:

```text
J-AbuTaifeha
```

Repository yang relevan:

```text
MyFirstProject
Julian-s-Calculator
I-m-Good-at-Cyber-Security-
```

Pada tampilan terbaru repository tidak ditemukan informasi mencurigakan. Seluruh petunjuk justru berada pada **riwayat commit Git**.

---

# Analisis Repository Password Checker

Repository:

```text
I-m-Good-at-Cyber-Security-
```

Salah satu commit yang menarik:

```text
2ab6458
```

Perubahan kode:

Sebelumnya:

```python
print("Status: Strong Password! 🔒")
```

Sesudah dikompromikan:

```python
print("Think you are good at cyber security ?! You have just got hacked by Mythos !")
```

Dari commit tersebut diperoleh nama penyerang:

```text
Mythos
```

Commit berikutnya menghapus perubahan tersebut sehingga hanya dapat ditemukan melalui riwayat Git.

---

# Analisis Repository Calculator

Repository:

```text
Julian-s-Calculator
```

Commit penting:

```text
8b150e9
```

Perubahan yang dilakukan attacker:

Sebelumnya:

```python
print("Invalid operator!")
```

Sesudah dimodifikasi:

```python
print("Invalid operator! You didn't know that I've also hacked your bot? Try to use it ;)")
```

Pesan tersebut memberikan petunjuk baru bahwa **Telegram Bot Julian juga telah dikompromikan**.

---

# Memulihkan Username Telegram

Repository berikutnya:

```text
MyFirstProject
```

README terbaru hanya menampilkan username Telegram yang telah disensor:

```text
@##########_bot
```

Namun pada commit lama ditemukan isi README sebelumnya:

```text
@AbuTa1f3ha_###
```

Gabungkan kedua potongan tersebut:

```text
@AbuTa1f3ha_###
@##########_bot
```

Hasil akhirnya adalah:

```text
@AbuTa1f3ha_bot
```

---

# Verifikasi Telegram Bot

Username tersebut mengarah ke Telegram Bot:

```text
@AbuTa1f3ha_bot
```

Bot memiliki nama:

```text
J-AbuTa1f3ha
```

Pada saat pengujian, bot tidak merespons perintah seperti:

```text
/start
/help
/flag
```

Hal ini kemungkinan disebabkan backend bot sudah tidak aktif. Namun, keberadaan bot beserta username-nya telah dapat diverifikasi melalui riwayat repository Git sehingga jalur OSINT tetap valid.

---

# Penyusunan Flag

Seluruh petunjuk akhirnya mengarah pada flag:

```text
KaliTeam{1_th1nk_y0u_kn0w_051NT!}
```

---

# Flag

```text
KaliTeam{1_th1nk_y0u_kn0w_051NT!}
```

---

