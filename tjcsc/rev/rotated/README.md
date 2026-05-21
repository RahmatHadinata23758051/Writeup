# Writeup - rev/rotated

## Deskripsi Challenge
Challenge ini memberikan sebuah file bernama `chall` yang diidentifikasi sebagai data mentah. Tujuan kita adalah menemukan flag yang tersembunyi di dalamnya.

## Analisis Awal
1.  **Identifikasi File**: Menjalankan perintah `file chall` memberikan hasil `data`. Ini menunjukkan bahwa file tersebut bukan binary ELF standar atau telah dimodifikasi.
2.  **Strings**: Menjalankan `strings chall` menunjukkan banyak karakter yang terlihat seperti binary yang teracak, namun ada petunjuk menarik seperti `rmu>`.
3.  **Rotasi Byte**: Mengingat judul challenge "rotated", saya mencoba menganalisis apakah ada rotasi byte. Setelah membandingkan header `chall` dengan header standar ELF (`7f 45 4c 46`), ditemukan bahwa setiap byte dalam file tersebut telah digeser (Caesar shift) sejauh `0x1d`.
    -   `0x9c` (byte pertama `chall`) - `0x1d` = `0x7f`
    -   `0x62` (byte kedua `chall`) - `0x1d` = `0x45` ('E')
    -   `0x69` (byte ketiga `chall`) - `0x1d` = `0x4c` ('L')
    -   `0x63` (byte keempat `chall`) - `0x1d` = `0x46` ('F')

## Dekripsi dan Unpacking
1.  **Dekripsi**: Saya membuat script untuk mengurangi setiap byte di `chall` dengan `0x1d`. Hasilnya adalah sebuah file ELF yang valid.
2.  **Unpacking**: File ELF hasil dekripsi ternyata dipack menggunakan UPX (`UPX!`). Saya melakukan unpacking menggunakan perintah `upx -d`.

## Analisis Binary
1.  **Fungsi Main**: Setelah di-unpack, binary tersebut sangat sederhana. Fungsi `main` hanya melakukan hal berikut:
    -   Membuat file bernama `script.sh`.
    -   Menulis sebuah script bash yang sangat terobfuskasi ke dalam file tersebut.
    -   Menutup file.
2.  **Analisis Script Bash**: Script dalam `script.sh` menggunakan teknik *parameter expansion* bash untuk menyembunyikan perintah aslinya. Inti dari script tersebut adalah:
    ```bash
    printf 'H4sIA...' | base64 -d | gunzip -c | bash
    ```
3.  **Ekstraksi Flag**:
    -   Mendekode string Base64 dan melakukan dekompresi Gzip menghasilkan perintah bash: `echo "Looking for a flag?" # dGpjdGZ7YjQ1aF9kM2J1Nl9tNDU3M3J9Cg==`.
    -   Flag disembunyikan dalam komentar sebagai string Base64: `dGpjdGZ7YjQ1aF9kM2J1Nl9tNDU3M3J9Cg==`.
    -   Mendekode string tersebut menghasilkan flag akhir.

## Flag
<FLAG>tjctf{b45h_d3bu6_m4573r}</FLAG>
