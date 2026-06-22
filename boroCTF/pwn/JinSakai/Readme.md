Writeup Jin Sakai - boroCTF (Pwn)

Tantangan ini mengeksplorasi dua kelemahan fundamental dalam bahasa C: Buffer Overflow (Struct Overwrite) dan Integer Overflow.

Analisis Vulnerability

1. Phase 1 - Struct Member Overwrite

Pada fungsi fight_phase1(), terdapat struct penampung state game:

struct GameState {
    char buffer[32];
    int samurai_hp;
};


Fungsi gets(state.buffer) digunakan untuk membaca input player. Karena fungsi gets tidak membatasi jumlah karakter yang dibaca, kita bisa melampaui batas array buffer[32] dan menimpa variabel yang berada tepat di bawahnya dalam memori, yaitu state.samurai_hp.

Kondisi untuk lolos ke fase berikutnya:

if (state.samurai_hp <= 0) {
    printf("TRANSITION|\n");
}


Kita cukup mengirimkan padding sebanyak 32 byte diikuti oleh 4 byte NULL (\x00\x00\x00\x00) agar nilai samurai_hp berubah menjadi 0.

2. Phase 2 - Signed Integer Overflow

Pada fungsi fight_phase2(), bos memiliki darah INT_MAX ($2147483647$ atau 0x7fffffff).
Kita diberikan opsi untuk menambahkan item pemulih darah ke bos:

samurai_hp += amount;


Jika kita berhasil mengubah darahnya menjadi tepat INT_MIN ($-2147483648$ atau 0x80000000), kita menang dan mendapatkan flag.
Dalam perhitungan signed 32-bit integer:


$$\text{INT\_MAX} + 1 = \text{INT\_MIN}$$

$$2147483647 + 1 = -2147483648$$

Mengisi input drop dengan angka 1 langsung memicu pembagian overflow yang dicari.

Langkah Eksploitasi

Lokal Test (One-Liner)

python3 -c "import sys; sys.stdout.buffer.write(b'A'*32 + b'\x00'*4 + b'\n3\n1\n2\n1\n')" | ./boss


Remote Exploit (Menggunakan Python)

Jalankan script exploit otomatis yang telah disediakan:

python3 solve.py REMOTE


Dan flag berhasil dibaca langsung dari server target.

boroCTF{gh0st_0f_3xpl01t4t10n}
