# Well Well Well

Challenge ini bukan soal exploit service secara langsung. Service `nc 45.130.164.173 30203` hanya jadi quiz checker. Kuncinya adalah membedah artefak forensik yang diberikan, menemukan IOC yang benar, lalu menjawab semua pertanyaan berdasarkan bukti.

## Langkah awal

Artefak yang diberikan cuma satu file:

- `well-well-well.tar.gz`

Recon cepat:

- `file well-well-well.tar.gz`
- `tar -tzf well-well-well.tar.gz`

Hasilnya menunjukkan ini adalah snapshot filesystem Linux yang berisi beberapa direktori penting seperti:

- `/var/log`
- `/home/ztz`
- `/etc`
- `/tmp`
- `/var/tmp`

Begitu konek ke service `nc`, pertanyaan pertama langsung memberi petunjuk bahwa yang dicari adalah penyebab kompromi pada mesin.

## Triage artefak

Dari isi home directory user `ztz`, ada beberapa proyek development. Yang paling menarik adalah:

- `/home/ztz/dev/site`

Di sana ada proyek Node.js dengan `package.json`, `package-lock.json`, `node_modules`, dan log npm. Dari `.bash_history` terlihat alur aktivitas user:

```bash
npm install
npx drizzle-kit generate
npx drizzle-kit migrate
npm run dev
git init
git branch -m main
git add .
git commit -m "Initial Commit"
```

Itu langsung menyempitkan fokus ke supply-chain compromise saat `npm install`.

## Menemukan paket jahat

Di `package-lock.json` terlihat dependency lokal yang tidak biasa:

- `fast-http-client` direferensikan dari file lokal
- paket itu bergantung ke `acme-util`, juga dari file lokal

Path penting:

- `/home/ztz/dev/site/node_modules/fast-http-client/package.json`
- `/home/ztz/dev/site/node_modules/acme-util/package.json`

Isi `package.json` asli dari tarball `acme-util` menunjukkan ada `postinstall`:

```json
"scripts": {
  "postinstall": "node 13fa9e8fd23400de798f72da608a8dbf.js"
}
```

Jadi file yang dieksekusi otomatis saat instalasi adalah:

- `/home/ztz/dev/site/node_modules/acme-util/13fa9e8fd23400de798f72da608a8dbf.js`

Nama paket jahatnya adalah:

- `acme-util`

## Analisis malware

File JavaScript obfuscated itu melakukan beberapa hal penting:

1. Menentukan project root dari `INIT_CWD`.
2. Membaca file `.env` di root proyek.
3. Mengenkripsi isi environment dengan `createCipheriv`.
4. Mengirim hasilnya lewat HTTP ke host internal.
5. Mengunduh dan memasang persistence berupa Git hook `post-commit`.
6. Menghapus jejak `postinstall` dari package agar terlihat normal setelah instalasi.

IOC dari malware utama:

- Host tujuan: `192.168.18.144`
- Port: `1337`
- Path exfil: `/collect`
- Stage path: `/post-commit.sh`
- Algoritma enkripsi: string literal di kode adalah `aes-256-cbc`
- Format jawaban checker untuk algoritma: `AES-CBC`
- Key/IV malware utama:
  - `2b997a77b33d893acba0c60e609ff7bf`
  - `138e100e33926c9a`

Format checker untuk Q5:

```text
2b997a77b33d893acba0c60e609ff7bf:138e100e33926c9a
```

## Persistence

Malware menulis persistence ke:

- `/home/ztz/dev/site/.git/hooks/post-commit`

Hook ini berisi shell script yang:

- mengambil URL remote Git
- mengambil commit hash
- mengambil author
- mengambil branch
- mengambil daftar file yang berubah
- membaca konten file yang berubah
- meng-encode konten ke base64
- mengenkripsi payload
- mengirimnya ke `http://192.168.18.144:1337/sync`

Key dan IV yang dipakai hook:

- Key: `0123456789abcdef0123456789abcdef`
- IV: `abcdef0123456789`

Format checker untuk Q7:

```text
0123456789abcdef0123456789abcdef:abcdef0123456789
```

## Jawaban final ke service

Urutan jawaban yang benar:

1. `acme-util`
2. `/home/ztz/dev/site/node_modules/acme-util/13fa9e8fd23400de798f72da608a8dbf.js`
3. `/home/ztz/dev/site/.git/hooks/post-commit`
4. `192.168.18.144:1337`
5. `2b997a77b33d893acba0c60e609ff7bf:138e100e33926c9a`
6. `AES-CBC`
7. `0123456789abcdef0123456789abcdef:abcdef0123456789`

## Flag

```text
THEM?!CTF{y3h..INSINAn1mie2;/:j92019p:SAD912j3op:dlamdo0912-41[4jmpAif10pri1;r12r1rh8012r}
```
