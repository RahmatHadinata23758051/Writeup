# BroncoCTF 2026 - Super Secure Server (Web)

## Analisis
Tantangan ini menyajikan sebuah halaman login yang mengklaim sangat aman karena username disembunyikan. Namun, pemeriksaan pada kode sumber sisi klien (client-side script) mengungkapkan bahwa aplikasi mengambil kredensial langsung dari sebuah endpoint API untuk melakukan komparasi string sebelum mengirimkan status otentikasi ke backend.

## Vulnerability Point
Aplikasi mengalami kerentanan **Information Disclosure / Broken Authentication**. Endpoint API sensitif `/api/config` dibiarkan terbuka untuk publik tanpa mekanisme otorisasi, mengekspos username dan password secara mentah (plaintext) ke sisi klien.

## Langkah Eksploitasi
1. Melakukan request ke endpoint `/api/config` menggunakan `curl` untuk mengambil data JSON berisi kredensial.
2. Mendapatkan kredensial berupa:
   - Username: `SuperSecretUser`
   - Password: `rji32orj932r3209r233sqmet4v2cxbns8`
3. Mengirimkan request POST ke `/login` dengan payload `{"authenticated": true}` atau melakukan login langsung via browser menggunakan kredensial tersebut untuk mendapatkan flag.
