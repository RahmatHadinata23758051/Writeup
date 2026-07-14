# Online Over-Sharer

**Category:** OSINT  
**Flag:** `bronco{0v3r5h4r1n6_m4k3s_m3_8lu3}`

## Challenge

Jenna membuat akun Instagram untuk membagikan kehidupannya bersama anjingnya, Blue. Informasi dari posting tersebut harus digunakan untuk menjawab dua tahap pertanyaan verifikasi pada web challenge.

Target akun:

```text
jenna_and_blue
```

Endpoint challenge:

```text
/check1
/check2
```

## 1. Memeriksa source web

Halaman utama dapat diambil dengan:

```bash
curl -s https://broncoctf-online-over-sharer.chals.io/
```

JavaScript pada halaman menunjukkan dua request POST.

Tahap pertama:

```javascript
fetch("/check1", {
  method: "POST",
  headers: {"Content-Type":"application/json"},
  body: JSON.stringify({
    username,
    firstDogBreed,
    gradDate,
    dogSiblings
  })
})
```

Tahap kedua:

```javascript
fetch("/check2", {
  method: "POST",
  headers: {"Content-Type":"application/json"},
  body: JSON.stringify({
    username,
    building,
    watchFrom,
    voiceActor
  })
})
```

Dengan source ini, kita mengetahui persis informasi OSINT yang harus dikumpulkan.

## 2. Mengumpulkan jawaban tahap pertama

Posting akun memberikan beberapa informasi langsung:

- Blue adalah seekor **basset hound**.
- Jenna akan lulus pada **Juni 2026**.
- Blue memiliki **2 saudara**.

Payload tahap pertama:

```json
{
  "username": "jenna_and_blue",
  "firstDogBreed": "basset hound",
  "gradDate": "06/2026",
  "dogSiblings": "2"
}
```

Request:

```bash
curl -i -s \
  -X POST 'https://broncoctf-online-over-sharer.chals.io/check1' \
  -H 'Content-Type: application/json' \
  --data '{
    "username":"jenna_and_blue",
    "firstDogBreed":"basset hound",
    "gradDate":"06/2026",
    "dogSiblings":"2"
  }'
```

Tahap ini mengembalikan HTTP `200`, sehingga seluruh jawaban pertama benar.

## 3. Menjawab tahap kedua

### Favorite campus view

Pertanyaannya:

```text
What building gives your favorite view of SCU's campus?
```

Dari posting dan pencocokan sudut pandang kampus, jawabannya adalah:

```text
Kenna Hall
```

### Lokasi Blue saat wisuda

Caption menyebut Blue akan menonton wisuda dari:

```text
grandmas house
```

### Pengisi suara teman berwarna pink

Acara masa kecil yang dimaksud adalah *Blue's Clues*. Teman berwarna pink/ungu adalah Magenta. Pengisi suara aslinya:

```text
Koyalee Chanda
```

Payload tahap kedua:

```json
{
  "username": "jenna_and_blue",
  "building": "Kenna Hall",
  "watchFrom": "grandmas house",
  "voiceActor": "Koyalee Chanda"
}
```

Request final:

```bash
curl -s \
  -X POST 'https://broncoctf-online-over-sharer.chals.io/check2' \
  -H 'Content-Type: application/json' \
  --data '{
    "username":"jenna_and_blue",
    "building":"Kenna Hall",
    "watchFrom":"grandmas house",
    "voiceActor":"Koyalee Chanda"
  }'
```

Output:

```text
bronco{0v3r5h4r1n6_m4k3s_m3_8lu3}
```

## Ringkasan Jawaban

```text
Username                 : jenna_and_blue
First dog breed          : basset hound
Graduation               : 06/2026
Dog siblings             : 2
Favorite campus building : Kenna Hall
Graduation watch location: grandmas house
Original voice actor     : Koyalee Chanda
```

## Flag

```text
bronco{0v3r5h4r1n6_m4k3s_m3_8lu3}
```
