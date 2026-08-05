# Writeup CTF - Robots

## Informasi Challenge

- **Judul:** Robots
- **Deskripsi:**

> Our servers have evolved. They no longer see code; they see the glitch in your biological existence.
>
> **Task:** Prove your worth to the Silicon Intelligence. If you can still find your "humanity" in the rubble we've logged.

- **Target:**
  ```
  http://438c.chall.kali-team.online:8001/
  ```

---

# Ringkasan Kerentanan

Challenge ini memanfaatkan petunjuk yang terdapat pada file `robots.txt`. Saat mengakses halaman utama, tidak ditemukan informasi sensitif maupun flag. Namun, judul challenge **Robots** serta isi halaman mengarahkan peserta untuk memeriksa file `robots.txt`.

Di dalam `robots.txt` terdapat petunjuk mengenai **Googlebot**, yang mengindikasikan bahwa server kemungkinan memberikan respons berbeda berdasarkan nilai **User-Agent** pada HTTP request.

Dengan memalsukan `User-Agent` menjadi `Googlebot`, server mengembalikan konten yang berbeda dan menampilkan flag.

---

# Langkah Penyelesaian

## 1. Cek halaman utama

```bash
curl http://438c.chall.kali-team.online:8001/
```

Output hanya menampilkan halaman HTML berisi pesan mengenai manusia dan AI, tanpa adanya flag.

---

## 2. Cek file `robots.txt`

```bash
curl http://438c.chall.kali-team.online:8001/robots.txt
```

Hasilnya menampilkan isi `robots.txt` beserta petunjuk yang menyebutkan **Googlebot**, namun belum menampilkan flag.

---

## 3. Ubah User-Agent menjadi Googlebot

Karena terdapat petunjuk mengenai Googlebot, kirim ulang request dengan header **User-Agent** yang dipalsukan.

```bash
curl -i -A "Googlebot" http://438c.chall.kali-team.online:8001/robots.txt
```

Server kemudian memberikan respons yang berbeda dan menampilkan flag.

---

# Flag

```text
KaliTeam{4fa558c4-8125-4360-aa64-9592a72c921a}
```

---


