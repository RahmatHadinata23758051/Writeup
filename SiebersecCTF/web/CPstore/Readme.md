# Writeup: CP Store

Challenge ini melibatkan eksploitasi pada aplikasi Node.js yang menggunakan MySQL sebagai database. Terdapat dua kerentanan utama yang digunakan untuk mendapatkan flag: **SQL Injection via Type Confusion** pada proses login dan **Logic Flaw** pada sistem voucher diskon.

## Analisis Vulnerability

### 1. SQL Injection (mysql2 Object Injection)
Pada file `routes/auth.js`, proses login menggunakan `db.query` dengan placeholder `?`. Namun, aplikasi menggunakan `express.urlencoded({ extended: true })`, yang memungkinkan pengiriman objek melalui body request.
```javascript
const [rows] = await db.query(
  "SELECT * FROM users WHERE username = ? and password = ? LIMIT 1",
  [username, password]
);
```
Library `mysql2` memiliki fitur (atau perilaku) di mana jika sebuah objek dilewatkan ke placeholder `?`, ia akan diserialisasi menjadi format `key = value`. Dengan mengirimkan `password[password]=1`, query akan berubah menjadi:
`SELECT * FROM users WHERE username = 'techie_ernie67' and password = password = 1 LIMIT 1`
Dalam MySQL, `password = password` bernilai `true` (selama tidak NULL), dan `true = 1` juga bernilai `true`. Hal ini memungkinkan bypass login tanpa mengetahui password asli user `techie_ernie67`.

### 2. Discount Logic Flaw
Setelah login, user memiliki saldo default 100. Item `FLAG` berharga 1000. Terdapat fitur untuk mendapatkan voucher diskon 10% (`0.1`). 
Di `routes/cart.js`, total harga dihitung dengan menjumlahkan semua diskon yang ada di session:
```javascript
const discount = Object.values(req.session?.vouchers ?? {}).reduce((sum, discount) => sum + discount, 0);
// ...
total *= 1 - Math.min(discount, 1);
```
Karena kita bisa meminta voucher baru berkali-kali (`/voucher/issue`), kita bisa mengumpulkan 10 voucher unik (karena ada klaim `iat` di JWT) untuk mendapatkan diskon total 100% (`1.0`), sehingga harga `FLAG` menjadi 0.

## Langkah Eksploitasi

1. **Login Bypass**: Kirimkan POST request ke `/login` dengan body `username=techie_ernie67&password[password]=1`. Ambil session cookie-nya.
2. **Add to Cart**: Tambahkan item FLAG (ID 6) ke dalam keranjang.
3. **Generate Vouchers**: Kunjungi `/voucher/issue` sebanyak 10 kali untuk mendapatkan 10 kode voucher unik.
4. **Apply Vouchers**: Masukkan 10 voucher tersebut melalui POST `/voucher/apply`.
5. **Checkout**: Lakukan checkout. Karena diskon 100%, saldo tidak akan berkurang.
6. **Get Flag**: Lihat di `/inventory` untuk mengambil flag-nya.

Flag ditemukan: `sctf{h1_iM_3rn13_But_y0u_c4n_c4LL_M3_t3chiE_3rNie}`
