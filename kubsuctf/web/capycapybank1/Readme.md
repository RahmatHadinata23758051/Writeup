# CAPY-CAPY Bank 1 Writeup

## Ringkasan

Challenge ini bisa diselesaikan tanpa tahu password maupun PIN Mikhail.

Masalah utamanya ada dua:

1. `Flask SECRET_KEY` lemah dan bisa di-bruteforce dari cookie `session`.
2. Secret yang sama juga dipakai untuk menandatangani JWT `access_token_cookie`.

Begitu secret diketahui, kita bisa:

- forge JWT untuk login sebagai `mgalankov@4274`
- bypass PIN dengan memalsukan isi cookie `session` bagian `pending_signatures`

Setelah itu tinggal masuk ke akun Mikhail, buka histori transaksi/receipt, dan ambil artefak pembelian flag yang valid.

## Langkah 1: Enumerasi dasar

Halaman publik menunjukkan aplikasi Flask/Werkzeug.

Beberapa hal penting yang kelihatan dari interaksi awal:

- auth pakai cookie JWT bernama `access_token_cookie`
- ada cookie `session` milik Flask
- ada route internal seperti:
  - `/verify_transaction/<id>`
  - `/receipt/<id>`
  - `/buy_flag`
  - `/flag_shop`

Selain itu ada perilaku aneh pada `bank_session`: nilainya menentukan node/backend mana yang dipakai.

## Langkah 2: User enumeration di login

Halaman login membedakan dua kondisi:

- `Неверный пароль...` kalau username ada
- `Пользователь с логином ... не найден...` kalau username tidak ada

Dengan ini bisa dipastikan bahwa `mgalankov@4274` memang valid.

## Langkah 3: Bruteforce SECRET_KEY dari Flask session

Cookie `session` Flask bisa didecode sebagian, lalu dipakai buat brute force `SECRET_KEY`.

Secret yang ketemu:

```text
facetoface
```

Nilai ini tervalidasi untuk:

- signature cookie Flask `session`
- signature JWT `access_token_cookie`

## Langkah 4: Forge JWT untuk jadi Mikhail

Karena secret JWT sama, kita bisa bikin token sendiri:

- `username = mgalankov@4274`
- `sub = 4`

`sub` didapat dengan brute-force ringan ke `/dashboard` menggunakan JWT palsu sampai ketemu kombinasi yang valid.  
Ternyata Mikhail punya `sub=4` di node-node yang diuji.

Setelah itu dashboard Mikhail bisa diakses langsung.

Info penting dari akun Mikhail:

- account: `ACC004`
- email: `mgalankov@example.com`
- akses premium ke `/flag_shop`

## Langkah 5: Decode mekanisme bypass PIN

Saat user normal meminta signature lewat `/api/get_signature`, server mengirim cookie `session` baru.

Isi session itu ternyata menyimpan struktur seperti ini:

```json
{
  "pending_signatures": {
    "<signature>": {
      "amount": "...",
      "description": "...",
      "expires_at": ...,
      "issued_at": ...,
      "timestamp": ...,
      "to_account": "...",
      "user_id": ...
    }
  }
}
```

Artinya validasi final `/transfer` tidak benar-benar bergantung pada PIN secara server-side yang terpisah; dia percaya pada state di cookie `session`.

Karena secret Flask sudah diketahui, cookie ini bisa dipalsukan penuh.

## Langkah 6: Bypass PIN

Dengan session palsu yang berisi `pending_signatures` buatan sendiri, transaksi bisa langsung dikonfirmasi ke `/transfer` selama field ini konsisten:

- `to_account`
- `amount`
- `description`
- `transaction_timestamp`
- `transaction_signature`
- `user_id`

Untuk akun Mikhail ini berarti kita bisa:

- beli produk dari `/flag_shop`
- konfirmasi transaksi tanpa tahu PIN Mikhail

## Langkah 7: Ambil artefak pembelian flag

Dari dashboard/receipt Mikhail di node challenge pertama, ada transaksi sukses ke `FLAG_SHOP` dengan deskripsi:

```text
Покупка: Флаг от CTF задания
```

Receipt yang relevan:

- `/receipt/1906`

Di receipt itu ada `Токен offer` yang terlihat sebagai artefak valid hasil pembelian flag:

```text
6MjZHrCcebxsRUV44LtTlmJ12mQHVgkI
```

## Inti kerentanannya

Kalau disingkat:

- cookie Flask bisa di-forge karena secret lemah
- JWT juga bisa di-forge dengan secret yang sama
- PIN bisa dibypass karena approval state disimpan client-side dalam cookie yang ditandatangani lemah

Itu memberi full account takeover + payment authorization bypass.

## Catatan

Aku sengaja simpan langkah di atas dalam bentuk yang praktis dan bisa direproduksi lagi dengan cepat, tanpa bikin penjelasannya terlalu kaku.  
Kalau nanti mau, chain ini bisa dibungkus jadi satu script otomatis penuh.
