# Confundus - Web CTF Walkthrough

## Ringkasan
Target: `http://noauth.putcyberdays.pl:80/`  
Vulnerability utama: **JWT algorithm confusion** + validasi key yang bisa dipaksa jadi HMAC secret.

## Recon Singkat
1. Endpoint penting:
   - `/login`, `/signup`
   - `/home` (butuh auth)
   - `/flag` (butuh `role=admin`)
   - `/.well-known` (publish public key material)
2. Source menunjukkan:
   - Token dibuat sesuai `JWT_ALGORITHM` (default ES256).
   - Saat verify, fungsi membaca `alg` dari header token attacker, lalu memilih verifier berdasarkan nilai itu.
   - Jadi attacker bisa kirim token dengan `alg=HS256` walau server normalnya pakai ES256.

## Akar Masalah
Di `is_valid_JWS`, server:
1. Parse header token.
2. Ambil `header['alg']`.
3. Verifikasi signature memakai algoritma tersebut.

Tidak ada pinning ke algoritma server-side untuk token access.  
Ini membuka algorithm confusion.

Tambahan bug implementasi: material key publik ES256 dari `/.well-known` bisa dibentuk ulang menjadi byte secret HMAC yang diterima verifier HS256 bila formatnya:

`ecdsa-sha2-nistp256 <base64_key>\r\n`

Dengan itu, attacker bisa sign token HS256 valid.

## Exploit
1. Ambil `es256` dari `/.well-known`.
2. Bentuk secret HMAC:
   - `b"ecdsa-sha2-nistp256 " + es256_blob + b"\r\n"`
3. Forge JWT:
   - Header: `{"alg":"HS256"}`
   - Payload:
     - `iss: example.com`
     - `aud: example.com`
     - `exp/iat`: valid timestamp
     - `role: admin`
     - `sub: pwn`
4. Set sebagai cookie `access_token`.
5. Request `/flag`.

## Solver
Solver tersimpan di file:
- [solve.py](/home/nata/ctf/putcyber/web/confundus/app/solve.py)

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python /home/nata/ctf/putcyber/web/confundus/app/solve.py
```

## Flag
`putcCTF{Ju5T_w1nn1ng_t0k3Ns}`

