# Writeup: Skull (Misc/Jail) - BYUCTF

## Deskripsi Challenge
Pada challenge ini, kita diberikan koneksi netcat ke sebuah *restricted shell* bernama `sbash` (Safe Bourne Again Shell). Kita juga diberikan *source code* `jail.sh` yang menunjukkan bagaimana filter keamanan diterapkan. Tujuannya adalah menjalankan sebuah skrip lokal tak bernama untuk mendapatkan flag.

## Analisis Source Code (`jail.sh`)
Mari kita bedah restriksi gila yang diterapkan pada shell ini:
1. **Broken PATH:** `export PATH="/tmp"` membuat kita tidak bisa memanggil command standar (seperti `ls`, `cat`) tanpa *absolute path*.
2. **Filter Karakter Simbol:** Karakter penting seperti spasi, `.`, `*`, `$`, `=`, `<`, `>`, `&`, dan `;` diblokir mentah-mentah.
3. **Filter Huruf Kecil:** `elif [[ "$user_input" =~ [[:lower:]] ]]` memastikan **semua huruf kecil (a-z)** akan ditolak.
4. **Batas Panjang:** Input maksimal hanya 20 karakter.

## Strategi Bypass
Karena kita harus mengeksekusi skrip di dalam direktori saat ini (yang namanya dirahasiakan dan kita tidak tahu panjangnya), kita punya masalah: kita tidak bisa memakai `.` (titik) untuk `./script`, tidak bisa pakai `*`, dan tidak bisa mengetik abjad kecil sama sekali.

Untuk mengakalinya, kita bisa menggunakan kombinasi fitur ekspansi bawaan Bash:
1. **Tilde Expansion (`~+`)**: Di dalam Bash, `~+` akan otomatis diekspansi menjadi variabel `$PWD` (direktori kerja saat ini). Ini mem-bypass kebutuhan mengetik *absolute path* dan huruf kecil.
2. **Wildcard Tanda Tanya (`?`)**: Karena tanda bintang (`*`) diblokir, kita bisa menggunakan `?` yang berfungsi sebagai *wildcard* untuk satu karakter apa saja.

Dengan merangkai `~+/???...`, Bash akan mengekspansinya menjadi `/ctf/19xxxx/???...`. Jika jumlah tanda tanya cocok dengan panjang nama file *executable* di direktori tersebut, file itu akan langsung tereksekusi!

## Eksekusi
Kita melakukan iterasi panjang karakter menggunakan tanda tanya di shell target.

```bash
safe_bash> ~+/???
command failed
safe_bash> ~+/????
command failed
safe_bash> ~+/?????
command failed
safe_bash> ~+/??????
command failed
safe_bash> ~+/???????
# Output memunculkan banner "Welcome to my new bash..." lagi.
# Ini berarti file dengan panjang 7 karakter adalah `jail.sh` itu sendiri!
