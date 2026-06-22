# boroCTF 2026 - Mania (Pwn)

## Analisis Struktur Data
Program mendefinisikan dua struktur data yang memiliki ukuran alokasi memori yang identik pada heap manager (`0x48` atau 72 byte):

```c
struct imaginaryFriend {
    double rating;               // Offset 0
    char title[32];              // Offset 8
    char special_ability[32];    // Offset 40
};

struct realPerson {
    char firstName[32];          // Offset 0
    char lastName[32];           // Offset 32
    void (*conversate)();        // Offset 64
};

Kerentanan (Use-After-Free)Ketika pengguna memilih menu 4 (Ghost person), program melakukan free(RF) terhadap objek realPerson, namun tidak mengubah pointer global RF menjadi NULL. Ini menciptakan kondisi Dangling Pointer.Karena mekanisme tcache pada glibc heap manager, alokasi memori berikutnya dengan ukuran yang sama akan menggunakan kembali alamat memori (chunk) yang baru saja dibebaskan tersebut. Saat menu 1 (Imagine friend) dipilih, objek imaginaryFriend baru ditempatkan tepat di atas memori bekas realPerson.Dengan menghitung jarak offset, variabel special_ability (offset 40) tumpang tindih dengan function pointer conversate (offset 64). Jarak bersih dari awal pengisian buffer special_ability menuju function pointer tersebut adalah $64 - 40 = 24$ byte.Langkah EksploitasiAlokasikan objek realPerson (Menu 3).Bebaskan objek tersebut untuk memasukkannya ke dalam list tcache (Menu 4).Alokasikan objek imaginaryFriend (Menu 1).Isi data title seadanya, kemudian pada special_ability kirimkan padding sebanyak 24 byte diikuti oleh alamat fungsi idealConversation (0x00401731).Jalankan menu 5 (Interact) untuk mengeksekusi function pointer conversate yang kini telah berubah arah menuju fungsi pemanggil shell.
