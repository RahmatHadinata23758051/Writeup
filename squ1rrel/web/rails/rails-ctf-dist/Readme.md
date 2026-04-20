# Writeup - web/rails

## Ringkasan
Challenge ini punya dua bug yang kalau digabung jadi full chain:
1. **Unsafe constantize** di endpoint `/show/:resource`.
2. **Auth JWT lemah** di middleware admin (cukup valid signature, tanpa validasi claim).

Terus ada bug kecil lagi di controller admin:
- Filter blokir `id == "1"` bisa dibypass pakai input seperti `01`, tapi query DB tetap resolve ke row `id=1`.

Kombinasi tiga hal itu langsung ngasih flag.

## Enumerasi Awal
Endpoint yang hidup dan menarik:
- `GET /up` -> health check.
- `GET /admin` -> `401 Missing Admin Authentication Cookie`.
- `GET /show/:resource` -> endpoint dinamis.

Dari source challenge:
- `ShowController#index` membentuk nama class dari user input:
  - `resource_name = @resource + "Module"`
  - `resource_name.constantize.new.show`
- Ada class `JWTModule < JWTSecret`.
- `JWTSecret#show` return secret JWT (ENV `JWT_SECRET` atau random saat boot).

Artinya `/show/JWT` akan memanggil `JWTModule#show` yang mewarisi method dari `JWTSecret` dan membocorkan signing key.

## Analisis Bug

### 1) Secret Disclosure via constantize
`/show/JWT` mengembalikan secret signing JWT aplikasi.

### 2) Weak JWT Validation di `/admin`
Middleware `AdminAuth` hanya melakukan:
- Ambil cookie `auth`
- `JWT.decode(token, hmac_secret, true, { algorithm: 'HS256' })`

Tidak ada cek role/admin claim sama sekali. Jadi asal token ditandatangani dengan secret yang benar, request dianggap lolos.

### 3) ID Guard Bypass
Di `Admin::PostsController#index`:
- Jika `id == "1"` -> raise error.
- Lalu query: `Post.where(id: params[:id]).first`

Input `01` tidak sama dengan string literal `"1"`, jadi guard tidak aktif. Tapi DB tetap menafsirkan nilai itu sebagai id 1, sehingga post terlarang tetap terbaca.

## Langkah Eksploitasi

1. Leak secret:
   - Request `GET /show/JWT`
2. Forge JWT HS256 dengan secret tadi:
   - payload bebas (misal `{ "user": "admin" }`)
3. Akses endpoint admin dengan cookie `auth=<token>`
4. Bypass guard id:
   - `GET /admin/posts?id=01`
5. Ambil `data.content` -> flag.

## Solver
File solver sudah disimpan di:
- `solver.py`

Cara pakai:
```bash
source /home/nata/ctf_env/bin/activate
cd /home/nata/ctf/squ1rrel/web/rails/rails-ctf-dist
python3 solver.py
```

Opsional target custom:
```bash
python3 solver.py https://rails.squ1rrel.dev
```

## Output Flag
Flag yang didapat dari eksploitasi valid:

`squ1rrel{rails?_in_my_ctf???}`

## Catatan Hardening
Kalau ini aplikasi beneran, perbaikannya:
- Jangan pakai `constantize` dari input user.
- Jangan expose class sensitif melalui endpoint generik.
- JWT admin wajib validasi claim (`role == admin`, `exp`, `aud`, dll).
- Hindari guard berbasis string literal untuk ID, gunakan check yang konsisten dengan tipe data.
