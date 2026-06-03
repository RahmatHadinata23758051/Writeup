# Writeup Bite

Challenge ini modelnya forensic berantai. Bukan cuma cari satu file lalu grep flag, tapi harus bedah image AD1, email client, history browser, binary dropper, payload ransomware, sampai decrypt file korban dan jawab semua pertanyaan di service.

## Ringkasan alur

Korban kena phishing lewat email bertema cheat game. Dari email itu korban buka link MEGA, download `bite.zip`, lalu menjalankan `bite.exe`. File itu ternyata dropper Windows yang mengambil payload terenkripsi dari resource internal, mendekripsinya dengan RC4, lalu menjatuhkannya sebagai `svchost.exe` di `%TEMP%`. Payload utamanya adalah ransomware berbasis Go yang mengenkripsi file Desktop dengan AES-128-CBC dan menambah ekstensi `.snake`.

Setelah semua pertanyaan di service dijawab, flag yang keluar adalah:

`THEM?!CTF{momen_ketika_bikin_challenge_4jam_sebelum_mulai_._mana_lama_banget_lagi_boot_windowsnya}`

## 1. Recon awal

Artefak utamanya adalah file `bite.ad1`, jadi langkah pertama saya identifikasi tipe file dan mount isinya.

Contoh command yang dipakai:

```bash
file bite.ad1
ad1info -i bite.ad1 -t > ad1_tree.txt
ad1mount -i bite.ad1 -m mnt_ad1
```

Dari tree dan hasil mount kelihatan ini image Windows user `felisa`. Folder pentingnya ada di:

- `Users/felisa/Desktop`
- `Users/felisa/AppData/Roaming/Thunderbird`
- `Users/felisa/AppData/Local/Microsoft/Edge`
- `Windows/Prefetch`
- `Windows/appcompat/Programs/Amcache.hve`

Di Desktop langsung kelihatan ciri infeksi:

- `README_DECRYPT.txt`
- beberapa file berakhiran `.snake`

## 2. Ransom note dan MachineGuid

Ransom note memberi banyak petunjuk awal. Dari file ini bisa diambil:

- nama note: `README_DECRYPT.txt`
- alamat Bitcoin: `bc1qsnek55m3l0v3r1337deadbeef00000000000`
- MachineGuid korban: `2ec8f83b-8ec8-453b-8c2f-5a6a1773fe8b`
- jumlah file terenkripsi di Desktop: 4

Registry key untuk MachineGuid juga standar Windows:

`HKLM\SOFTWARE\Microsoft\Cryptography`

## 3. Analisis email phishing

Karena deskripsi bilang korban kena cryptolocker dan ada browser + mail artefact, saya cek Thunderbird profile korban.

Hal yang ditemukan:

- email client: `Thunderbird`
- sender: `support@gamemaster.pro`
- subject: `Your FREE Aimbot License Key Inside!`
- waktu email diterima: `2026-05-25 07:15:00` UTC
- konfigurasi POP3 pakai port `1110`

Di body email ada link download malware:

`https://mega.nz/folder/N3lBVQQT#AeiSi9X_pkYU29Xxz4tAzg`

Itu jawaban penting untuk Q1 dan jadi titik masuk seluruh kasus.

## 4. Riwayat download Edge

Browser history Edge disimpan sebagai SQLite, tapi untuk challenge begini saya lebih nyaman pakai parser yang tetap bisa baca record yang sudah berubah atau tidak enak dibuka langsung.

Saya pakai `sqlite_dissect` ke database `History` dan fokus ke tabel download. Dari sana ketemu:

- file yang disimpan: `C:\Users\felisa\Downloads\bite.zip`
- waktu download selesai: `2026-05-29 12:40:05` UTC

Ini menjawab pertanyaan soal path download dan timestamp download malware.

## 5. Ambil file malware dari link MEGA

Link yang ada adalah public folder MEGA. Saya query API MEGA untuk list node, decrypt metadata folder, lalu ambil file di dalamnya. Isi foldernya ternyata cuma satu file penting:

- `bite.exe`

Setelah file didapat, saya hash:

`fba69a6f8d51e9cf32db3b8f5dc7750c80745b0865e4d22dcd0cb8223a98b6ab`

## 6. Analisis dropper `bite.exe`

Binary ini PE Windows biasa. Dari string dan import table langsung kelihatan dia bermain di resource section.

Temuan penting:

- API untuk cari resource: `FindResourceA`
- resource ID: `100`
- resource type: `RCDATA`
- key RC4 hardcoded: `e456bac6661a5c29`
- output filename setelah decrypt: `svchost.exe`

Alurnya sederhana:

1. load resource terenkripsi dari executable
2. decrypt dengan RC4
3. tulis hasilnya ke `%TEMP%\\svchost.exe`
4. eksekusi payload itu

## 7. Recover payload ransomware

Resource `RCDATA` ID `100` saya extract lalu decrypt dengan RC4 key tadi. Hasilnya payload kedua.

Hash payload hasil recover:

`05bea37c91062cefcd3f845b54d971090cf3eb89ce6a9e07cb5095a9e4700220`

Dari hasil triage:

- bahasa: `Go`
- password hardcoded: `thisissafepasswordbronocapongod`

Selain itu dari string dan reversing logika enkripsinya, ketemu:

- hash derivation: `sha256`
- mode enkripsi: `AES-128-CBC`
- padding: `PKCS7`
- ekstensi output: `.snake`

## 8. Derive key dan IV ransomware

Bagian ini yang paling penting secara teknis. Dari binary diketahui password hardcoded dan MachineGuid dipakai dalam derivasi kunci. Setelah beberapa percobaan terhadap sample file `.snake`, kombinasi yang valid adalah:

- key = 16 byte pertama dari `sha256(password + guid)`
- iv = 16 byte pertama dari `sha256(guid + password)`

Dengan:

- password = `thisissafepasswordbronocapongod`
- guid = `2ec8f83b-8ec8-453b-8c2f-5a6a1773fe8b`

Didapat:

- key: `a2801dc6ee7154284c308f52f8cadb7e`
- iv: `bc10b391f3054bb1481bd9647bf4b453`

Saya validasi dengan decrypt file `.snake` dan hasil plaintext langsung cocok magic byte aslinya.

## 9. Decrypt file korban

Begitu key dan IV benar, file Desktop bisa didecrypt. Salah satu yang paling penting adalah:

- `Project Alpha.docx.snake` -> `Project Alpha.docx`

Nama file terenkripsi yang diminta service adalah:

`Project Alpha.docx.snake`

## 10. Prefetch

Prefetch `BITE.EXE-*.pf` dipakai untuk jawab execution artefact:

- run count: `1`
- last run UTC: `2026-05-29 12:41:27`
- SHA-256 prefetch:
  `95871f0fe8437b2d229ea960edd9581973af2c5b635555288c5774c6597c04b2`

## 11. Metadata DOCX dan jebakan Q34

Awalnya saya kira Q34 minta metadata `docProps/core.xml`, karena di sana memang ada:

- creator: `Felisa`
- created: `2013-12-23T23:15:00Z`
- AppVersion: `16.0000`

Tapi ternyata jawaban itu salah.

Kuncinya ada di isi dokumennya sendiri, bukan cuma properti file. Di `word/document.xml` terdapat header yang secara eksplisit menulis:

- `Author: Felisa`
- `Date: 2026-05-28`
- `Version: 6.7`

Jadi format yang benar untuk Q34 adalah:

`Felisa_2026-05-28_6.7`

## 12. Jawaban final service

Urutan jawaban yang dipakai untuk replay ada di `solve.py`. Script itu tinggal konek ke service dan kirim semua jawaban berurutan sampai flag keluar.

## Flag

`THEM?!CTF{momen_ketika_bikin_challenge_4jam_sebelum_mulai_._mana_lama_banget_lagi_boot_windowsnya}`
