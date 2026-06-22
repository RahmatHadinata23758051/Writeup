# SiebersecCTF - Study Time (Reverse Engineering)

## Analisis
Diberikan sebuah script Python `homework.py` yang meminta input string sepanjang 50 karakter. Script ini mengambil data teks mentah dari API publik `https://catfact.ninja/breeds` sebagai string referensi. 

Melalui struktur percabangan `if` yang sangat dalam (nested), program mencocokkan setiap posisi indeks pada input user dengan posisi indeks tertentu pada string referensi dari API tersebut. Jika seluruh 50 karakter cocok, program akan mengembalikan nilai `True` yang berarti input tersebut adalah flag yang valid.

Karena data referensi bersifat statis (respons API dapat diprediksi/direplikasi) dan aturan pemetaan indeks (`answer[i] == data[j]`) ditulis secara eksplisit di kode, tantangan ini dapat diselesaikan dengan memetakan ulang seluruh indeks tersebut ke dalam sebuah array baru tanpa perlu menebak input secara manual.

## Langkah Penyelesaian
1. Kumpulkan semua pasangan indeks antara input (`answer`) dan string referensi (`my_homework...`) dari file `homework.py`.
2. Buat script otomasi `solve.py` yang melakukan request ke endpoint API yang sama.
3. Definisikan dictionary pemetaan indeks dan rekonstruksi string flag berukuran 50 karakter dari karakter-karakter respons API yang sesuai.
4. Jalankan script untuk mencetak flag.
