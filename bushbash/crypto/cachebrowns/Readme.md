# cachebrowns

## Ringkasan

`main.java` adalah source Java, bukan binary ELF. Server meminta password minimal 16 karakter lalu hanya memakai hasil `String.hashCode()` untuk autentikasi. Password 16 karakter printable dapat dibuat untuk hash yang sesuai.

## Proteksi Binary

`file main.java` melaporkan Java source UTF-8. `readelf` dan `ldd` menolak file karena ini bukan ELF, jadi PIE, NX, canary, RELRO, CET, ROP, serta offset stack tidak berlaku. Program berjalan melalui Java launcher (`java main.java`); Java 21 lokal cukup untuk menjalankan source ini walau komentar source menyebut Java 25.

## Analisis Program

Bagian autentikasi adalah:

```java
if (input.length() < 16) { ... }
if (auth(input.hashCode())) { ... }
```

`auth()` berjalan melalui daftar `Integer` berikut:

```java
for (Integer permittedHashcode : PERMITTED_HASHCODES) {
    if (permittedHashcode == inputHash) return true;
}
```

`String.hashCode()` menghitung `h = 31*h + character` dalam aritmetika signed 32-bit. Tidak ada pembandingan password asli ataupun salt.

## Vulnerability

Vulnerability-nya adalah autentikasi berbasis hash Java 32-bit yang tidak collision-resistant. Banyak string berbeda dapat memiliki hash yang sama.

Ada detail tambahan: `==` membandingkan referensi dua `Integer`, bukan nilai. Target hash besar yang pertama kali dicoba memang menghasilkan `Wrong password` karena hasil autoboxing bukan objek yang sama dengan elemen array. Nilai `-110` ada di rentang Java `Integer` cache default (`-128` sampai `127`), sehingga `input.hashCode()` yang menghasilkan `-110` di-autobox ke objek cache yang identik dan lolos.

## Primitive

- Preimage terkontrol untuk `String.hashCode() == -110`.
- Password berukuran tepat 16 byte printable ASCII.
- Autentikasi valid karena identitas `Integer(-110)` berasal dari cache Java yang sama.

## Strategi Exploit

Solver menetapkan semua 16 karakter ke spasi (`0x20`), lalu menyelesaikan residual hash pada tujuh karakter terakhir dalam basis 31. Digit residual selalu `0..30`; dengan menambahkan `0x20`, semua karakter tetap printable dan tidak ada newline.

Password yang dihasilkan solver saat ini adalah:

```text
          )2%64,
```

Sembilan karakter awal adalah spasi. Solver tidak mengandalkan password itu secara hardcoded: ia menghitung residual serta memverifikasi ulang hash sebelum mengirimkannya.

## Exploit Final

`solve.py` menyinkronkan prompt `> `, mengirim preimage, memastikan output berisi `Authenticated!`, lalu mencetak respons service. Alamat tidak di-hardcode dan ASLR tidak relevan karena ini challenge Java source.

## Cara Menjalankan

Aktifkan environment yang disediakan lalu jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
python3 solve.py GDB
python3 solve.py REMOTE HOST=34.40.133.67 PORT=7777
```

Mode lokal menjalankan `java main.java`. Jika `flag.txt` tidak tersedia secara lokal, autentikasi tetap bisa tervalidasi tetapi program akan mencetak `Could not read flag.txt`. Mode `GDB` dipertahankan sebagai mode launcher lokal; tidak ada native ELF/simbol GDB untuk dianalisis.

## Hasil

Service remote menghasilkan flag berikut setelah autentikasi:

```text
bushbash{doNt-Dr1nk-jav4-foR-br3kkie}
```

## Catatan Stabilitas

Eksploit tidak memakai race atau timing. `solve.py` memverifikasi hash secara lokal, memakai timeout 10 detik, dan berhenti dengan error jelas bila prompt atau autentikasi tidak sesuai.
