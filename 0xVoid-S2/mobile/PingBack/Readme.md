# PingBack

## Ringkasan

`PingBack.apk` punya `BroadcastReceiver` exported bernama `com.pingback.app.UnlockReceiver`. Receiver ini mengambil extra `auth` dan `seq`, memvalidasinya, lalu membuat key AES dari gabungan dua nilai tersebut. Kalau valid, receiver membaca `assets/signal.enc`, decrypt AES-CBC, dan menulis plaintext ke log tag `PingBack`.

Flag valid:

```
0xV0ID{p1ng_b4ck_r3c31v3r_unl0ck3d_v14_1nt3nt}
```

## File Challenge

```
PingBack.apk
```

Isi APK:

```
classes.dex
AndroidManifest.xml
resources.arsc
assets/signal.enc
META-INF/*
```

`assets/signal.enc` berukuran 48 byte dan merupakan ciphertext AES-CBC dengan padding PKCS#5/PKCS#7.

## Analisis Awal

Pemeriksaan awal:

```bash
file *
strings -a ./PingBack.apk | head -n 100
strings -a classes.dex
strings -el AndroidManifest.xml
```

Temuan string penting dari `classes.dex`:

```
AES/CBC/PKCS5Padding
SHA-1
SYNC-2026
-PING
auth
seq
signal.enc
auth_denied
decrypt_failed
PingBack
```

Manifest binary XML berisi receiver dan action:

```
com.pingback.app
.UnlockReceiver
com.pingback.ACTION_UNLOCK
exported
```

Jadi receiver bisa dipanggil dengan broadcast intent action `com.pingback.ACTION_UNLOCK`.

## Analisis Static

DEX kecil, jadi cukup diparse/disassemble manual. Class utama yang penting:

```
Lcom/pingback/app/UnlockReceiver;
```

Method yang relevan:

```
getExpectedAuth()
getExpectedSeq()
onReceive(Context, Intent)
<clinit>()
```

`getExpectedAuth()`:

```java
return "SYNC-2026".concat("-PING");
```

Jadi nilai `auth` yang benar:

```
SYNC-2026-PING
```

`getExpectedSeq()`:

```java
int v0 = 12;
v0 = v0 + (-1);
return v0;
```

Jadi nilai `seq` yang benar:

```
11
```

`<clinit>()` mengisi static field `IV` dengan payload `fill-array-data`:

```
0f 1e 2d 3c 4b 5a 69 78 87 96 a5 b4 c3 d2 e1 f0
```

## Analisis Dynamic

Receiver bisa dipanggil di device/emulator dengan:

```bash
adb shell am broadcast \
  -a com.pingback.ACTION_UNLOCK \
  -n com.pingback.app/.UnlockReceiver \
  --es auth SYNC-2026-PING \
  --ei seq 11

adb logcat -s PingBack:D
```

Tanpa emulator, alurnya bisa direproduksi lokal karena ciphertext `signal.enc`, IV, dan proses derivasi key sudah jelas dari bytecode.

## Algoritma Validasi atau Encoding

Alur `onReceive()`:

1. Ambil string extra `auth`, default `""`.
2. Ambil integer extra `seq`, default `0`.
3. Bandingkan `auth` dengan `getExpectedAuth()`.
4. Bandingkan `seq` dengan `getExpectedSeq()`.
5. Kalau salah, log `auth_denied`.
6. Kalau benar, buat material key:

```
SYNC-2026-PING11
```

7. Hitung SHA-1 dari material key.
8. Ambil 16 byte pertama sebagai AES-128 key.
9. Decrypt `assets/signal.enc` dengan:

```
AES/CBC/PKCS5Padding
IV = 0f1e2d3c4b5a69788796a5b4c3d2e1f0
```

Hasil plaintext inilah yang dilog ke tag `PingBack`.

## Penyusunan Solve Script

`solve.py` membaca `assets/signal.enc` langsung dari `PingBack.apk`, menghitung key dari `SHA1(b"SYNC-2026-PING11")[:16]`, lalu decrypt AES-CBC memakai IV dari `<clinit>()`.

Script mendukung beberapa environment:

1. `cryptography`, kalau tersedia.
2. `PyCryptodome`, kalau tersedia.
3. `openssl` CLI sebagai fallback.

## Cara Menjalankan

```bash
cd /mnt/data/PingBack
python3 solve.py
```

Output:

```
0xV0ID{p1ng_b4ck_r3c31v3r_unl0ck3d_v14_1nt3nt}
```

## Flag

```
0xV0ID{p1ng_b4ck_r3c31v3r_unl0ck3d_v14_1nt3nt}
```
