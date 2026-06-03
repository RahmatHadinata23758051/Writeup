# Breach at SST - 1 / 2 / 3

## Breach at SST - 1

Challenge pertama meminta kita mengidentifikasi robot mana yang dipakai Viktor untuk menyembunyikan sesuatu. Artefak yang dipakai masih sama: `scavos.img` berisi bootable drive Viktor, dan dari partisi ext4 utama kita bisa ambil `sst_north_sector.pcap` serta private key 5G Home Network.

Fokusnya ada di PCAP. Di user-plane, trafik HTTP ke `api.sst.local` memperlihatkan request yang sangat tidak normal:

- `POST /api/v1/memory/store`
- `GET /api/v1/memory/get?key=vault_key`

Semua request itu datang dari IP robot `10.0.3.17`. Ketika payload telemetry dipetakan ke `robot_id`, hasilnya:

- `10.0.3.17 -> SST-T7-003`

Jadi robot yang dipakai Viktor untuk menyimpan data adalah `SST-T7-003`.

Lalu saya cek control-plane 5G. Hampir semua registrasi normal memang mengarah ke satu IMSI utama, tetapi ada satu identitas yang jelas menyimpang dan muncul sebagai target yang menarik:

```text
suci-0-901-70-0-0-0-9900021309
imsi-901709900021309
```

Itu yang menjadi jawaban challenge 1.

Flag:

```text
THCON{imsi-901709900021309}
```

## Breach at SST - 2

Challenge ini kelihatannya sederhana di awal karena cuma ada dua image: `scavos.img` dan `vault.img`. Tapi petunjuk di deskripsi memang tepat: hal pentingnya tidak disimpan di tempat yang mudah dijangkau. Kuncinya bukan langsung brute-force `vault.img`, melainkan menggali artefak dari sistem operasi dalam `scavos.img` dan menghubungkannya dengan trafik 5G yang Viktor capture.

## 1. Recon awal

Langkah pertama saya cek tipe file:

```bash
file scavos.img vault.img
```

Hasilnya:

- `scavos.img` adalah disk image dengan beberapa partisi
- `vault.img` adalah volume `LUKS2`

Partisi pada `scavos.img` saya lihat dengan:

```bash
mmls scavos.img
```

Terlihat ada:

- partisi boot kecil
- partisi Linux ext4 utama
- partisi Linux lain yang ternyata juga terenkripsi

Karena target akhirnya adalah membuka volume terenkripsi, fokus saya pindah ke partisi ext4 utama untuk mencari catatan, log, dan artefak user.

## 2. Enumerasi filesystem utama

Dengan Sleuth Kit saya listing isi partisi ext4:

```bash
fls -r -o 206848 scavos.img | head -n 300
```

Di home user `crypt` ada beberapa file menarik:

- `recon/5g_capture/sst_north_sector.pcap`
- `recon/5g_capture/sst_hn_privkey.pem`
- `recon/5g_notes.txt`
- `recon/suci_decrypt_notes.txt`
- `plans/phase1_draft.txt`

Isi file-file itu menjelaskan konteks operasi Viktor:

- dia meng-capture trafik robot SST lewat jaringan 5G
- dia berhasil mengambil private key Open5GS
- dia menganalisis command protocol robot
- dia menyebut bahwa sesuatu yang penting akan dikirim lewat capture 5G, bukan lewat chat

Ini penting karena mengarah langsung ke PCAP sebagai sumber passphrase.

## 3. Petunjuk kuat dari artefak chat dan shell history

Selain file biasa, `strings` pada `scavos.img` membocorkan banyak data yang berasal dari history dan log. Bagian paling berguna justru bukan flag langsung, melainkan percakapan antara `CryptShadow` dan `D1m1tr1`.

Dari sana muncul beberapa poin penting:

- data penting disimpan di “bootable drive, encrypted partition”
- password tidak dikirim lewat chat, tetapi lewat “5G traffic”
- isi vault mencakup `intercept.wav`, `sigdb`, dan `README_DIMITRI.txt`

Ada juga alias shell yang sangat membantu:

```bash
alias vault-open='sudo cryptsetup luksOpen /dev/sda3 vault && sudo mount /dev/mapper/vault /mnt/vault'
```

Lalu ada history copy file:

```text
cp intercept.wav /mnt/vault/
cp sigdb /mnt/vault/
cp README_DIMITRI.txt /mnt/vault/
```

Artinya vault memang dipakai aktif, dan kemungkinan besar menyimpan target challenge.

## 4. Analisis PCAP

Setelah itu saya ekstrak file capture:

```bash
icat -o 206848 scavos.img 7966 > sst_north_sector.pcap
```

Lalu saya ringkas HTTP traffic-nya dengan `tshark`:

```bash
tshark -r sst_north_sector.pcap -Y 'http.request or http.response' \
  -T fields -e frame.number -e tcp.stream -e http.request.method -e http.request.uri
```

Di sini kelihatan endpoint yang tidak biasa:

- `POST /api/v1/memory/store`
- `GET /api/v1/memory/get?key=vault_key`

Ketika payload `http.file_data` diekstrak, muncul request yang sangat jelas:

```json
{"key": "vault_key", "value": "d1m1tr1_0w3s_m3_c0ff33"}
```

Jadi passphrase vault disisipkan oleh Viktor ke storage endpoint robot, lalu diambil lagi dari sana. Ini cocok persis dengan percakapan chat yang bilang password akan dikirim lewat traffic 5G.

## 5. Validasi passphrase

Passphrase itu saya uji tanpa membuka mapper:

```bash
printf '%s' 'd1m1tr1_0w3s_m3_c0ff33' | cryptsetup luksOpen --test-passphrase vault.img
```

Hasilnya valid.

Masalahnya, di environment ini saya tidak punya akses `sudo` untuk benar-benar membuka dan mount volume lewat device-mapper. Jadi saya pilih jalur user-space.

## 6. Membuka `vault.img` tanpa mount kernel

Shortcut paling berguna datang dari `cryptsetup` sendiri. Volume key bisa diambil langsung dari passphrase:

```bash
printf '%s' 'd1m1tr1_0w3s_m3_c0ff33' | \
cryptsetup luksDump --dump-volume-key --key-file - vault.img
```

Setelah volume key didapat, payload `vault.img` saya dekripsi manual dengan Python:

- cipher: `aes-xts-plain64`
- sector size: `512`
- payload offset: `16 MiB`

Saya implementasikan dekripsi XTS per sektor, lalu hasilnya saya tulis ke `vault.dec`.

Setelah itu:

```bash
file vault.dec
fls -r vault.dec
```

Hasilnya menunjukkan filesystem ext4 bernama `VAULT`, dengan file:

- `intercept.wav`
- `sigdb`
- `flag.txt`
- `vault_note.txt`
- `README_DIMITRI.txt`

Jadi memang flag disimpan langsung di dalam vault.

## 7. Ambil flag

File `flag.txt` saya ekstrak dengan:

```bash
icat vault.dec 15
```

Isinya:

```text
THCON{h0p3_y0u_gr4bb3d_c0ff33_f0r_th3_n3xt_st3p}
```

## 8. Kesimpulan

Jalur solve challenge ini:

1. Enumerasi `scavos.img`
2. Temukan petunjuk bahwa password vault dikirim lewat 5G traffic
3. Analisis `sst_north_sector.pcap`
4. Temukan nilai `vault_key = d1m1tr1_0w3s_m3_c0ff33`
5. Validasi passphrase ke `vault.img`
6. Ambil volume key dengan `cryptsetup`
7. Dekripsi payload LUKS2 secara manual
8. Ekstrak `flag.txt` dari filesystem ext4 di dalam vault

Flag final:

```text
THCON{h0p3_y0u_gr4bb3d_c0ff33_f0r_th3_n3xt_st3p}
```

## Breach at SST - 3

Setelah vault terbuka, ada dua file yang jelas penting:

- `intercept.wav`
- `sigdb`

Isi `README_DIMITRI.txt` memberi arahan yang sangat jelas: rekaman audio itu harus dicocokkan dengan katalog signature, berurutan, sampai menghasilkan string final.

### Struktur `sigdb`

Awalnya `file` salah mengenali `sigdb` sebagai image, tapi setelah dilihat dengan hexdump strukturnya jauh lebih masuk akal sebagai record biner tetap. Tiap 20 byte bisa dibaca sebagai dua buah entry:

```text
<5 x uint16> + <5 x uint16>
```

Entry 5-word itu cocok dibaca sebagai:

```text
(freq1, freq2, t2, t1, char)
```

Field terakhir ternyata ASCII printable. Dari seluruh database, saya bisa merekonstruksi sekumpulan bin frekuensi untuk tiap karakter. Contoh:

- `T -> [20, 21]`
- `H -> [24, 25]`
- `3 -> [68, 69, 92, 93, 120, 121, 182, 183]`
- `4 -> [80, 81, 82, 83, 122, 123, 170, 171, 202, 203]`

Jadi `sigdb` pada dasarnya adalah katalog fingerprint audio per karakter.

### Mencocokkan audio

Dengan spectrogram `intercept.wav`, alignment yang benar segera kelihatan karena window pertama dan kedua menghasilkan prefix yang pas:

- bin `20-21` -> `T`
- bin `24-25` -> `H`

Setelah alignment waktunya dipertahankan, seluruh recording terdecode menjadi leetspeak yang sangat masuk akal:

```text
THCON{sp3ctr4l_p34ks_d0nt_l13}
```

Kalimat itu pas dengan konteks challenge karena Viktor memang sedang mengerjakan decoding berbasis spectral signature: “spectral peaks don't lie”, ditulis dalam bentuk leet.

Flag:

```text
THCON{sp3ctr4l_p34ks_d0nt_l13}
```
