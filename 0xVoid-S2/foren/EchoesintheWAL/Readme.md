# Echoes in the WAL

Flag: `0xV01D{the_wal_keeps_old_promises}`

## Ringkasan artefak

`nightjar.db` adalah SQLite database dengan mode WAL. Database utama hanya menampilkan attachment terakhir:

```text
thread_id=17 revision=5 state=replaced
```

Itu bukan attachment yang dicari. `notification_history.log` memberi urutan kejadian:

```text
attachment ready [thread=17 revision=4 tx=47]
remote replacement [thread=17]
retention purge [thread=17]
```

Konfigurasi aplikasi menjelaskan format kriptografi:

```text
AES-256-GCM
key = SHA-256(android_id:thread_id:revision:committed_ms)
AAD = thread=<thread_id>;revision=<revision>
nonce = attachments.nonce
```

`device.xml` menyediakan Android ID `a91f32d06c74be18` dan timezone `Asia/Amman`. Timestamp yang dipakai untuk kunci adalah nilai `committed_ms` dari row/transaksi SQLite, bukan timestamp perkiraan.

## Recovery dari WAL

WAL memiliki page size 4096 byte dan 24 frame. Commit frame membentuk beberapa snapshot historis. Frame terakhir hanya merepresentasikan keadaan setelah replacement dan purge, sedangkan snapshot pada frame 13 masih berisi revisi 4 dengan status `ready`.

Snapshot tersebut mengembalikan row berikut:

```text
thread_id   17
revision    4
committed_ms 1784062991842
state       ready
nonce       8234adbb409685b959b31ab9
```

Nilai `txlog` untuk `tx=47` memiliki `committed_ms` yang sama. Payload revisi 4 diambil dari page WAL yang masih menyimpan row historis itu.

`solve.py` melakukan materialisasi frame WAL ke database sementara. File bukti asli tidak dibuka untuk operasi tulis dan tidak dimodifikasi.

## Decrypt attachment

Key material yang dipakai:

```text
a91f32d06c74be18:17:4:1784062991842
```

Setelah SHA-256, hasilnya dipakai sebagai AES-256-GCM key. AAD yang digunakan:

```text
thread=17;revision=4
```

GCM authentication berhasil, lalu plaintext terdeteksi sebagai ZIP (`PK\x03\x04`). ZIP berisi `handoff.txt` dan `telemetry.bin`.

Isi `handoff.txt` memuat:

```text
Recovery accepted. Historical attachment revision: 4
Flag: 0xV01D{the_wal_keeps_old_promises}
```

## Menjalankan solver

Aktifkan salah satu environment crypto yang tersedia, lalu jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Output:

```text
0xV01D{the_wal_keeps_old_promises}
```
