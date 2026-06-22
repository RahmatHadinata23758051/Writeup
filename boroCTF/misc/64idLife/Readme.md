64 is life (Misc)

Deskripsi Tantangan

Flag dipecah menjadi 64 bagian di dalam file 64.zip. Nama file dari pecahan tersebut di-encode menggunakan Base64 yang mewakili urutan potongan (index 1 hingga 64).

Analisis

Isi folder ctf_chunks setelah diekstrak berupa 64 file dengan nama Base64 seperti MQ== (1), Mg== (2), hingga NjQ= (64).

Saat memeriksa isi file:

File MQ== berisi Y40 (disusul banyak spasi).

File Mg== berisi m40 (disusul banyak spasi).

File NjQ= berisi 40 (disusul banyak spasi).

Karakter sesungguhnya dari potongan Base64 flag berada pada indeks karakter pertama setiap file. Angka 40 dan spasi di belakangnya merupakan padding sampah yang harus dibuang.

Solusi

Kita perlu membaca file dari index 1 hingga 64 secara berurutan, mengambil karakter pertama dari masing-masing file, menggabungkannya menjadi satu string Base64 yang utuh, lalu men-decode-nya.

Gunakan one-liner bash berikut untuk menyelesaikan tantangan secara instan:

for i in {1..64}; do cut -c1 ctf_chunks/$(echo -n $i | base64); done | tr -d '\n' | base64 -d


Hasil Akhir

String Base64 yang digabungkan: Ym9yb0NURntzMXh0eV9mMHVyX2IzdXR5fQ============

Hasil decode Base64: boroCTF{s1xty_f0ur_b3auty}
