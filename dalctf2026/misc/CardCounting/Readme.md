# Writeup: Card Counting - DalCTF 2026

## Deskripsi
Challenge ini adalah mini-game "Card Counting". Kita diminta untuk menebak jumlah total nilai kartu yang muncul di layar dalam beberapa level. Level-level awal cukup mudah, tapi level terakhir memunculkan 1000 kartu dengan gerakan yang sangat cepat dan acak, sehingga tidak mungkin dilakukan secara manual.

## Analisis
Dari file `game.js` yang disediakan, kita bisa melihat logika permainan:

1.  **PRNG (Pseudo-Random Number Generator):**
    Permainan menggunakan LCG (Linear Congruential Generator) untuk menentukan kartu yang muncul.
    ```javascript
    const s=1664525;
    const i=1013904223;
    const o=2147483647;
    let r=...; // Seed didapat dari server
    ```

2.  **Penentuan Kartu:**
    Fungsi `h()` digunakan untuk menghasilkan indeks kartu:
    ```javascript
    function h(){
        let t=63&r>>4;
        let e=t&15;
        if(e>9){e=16-e}
        let n=3&t>>4;
        r=r*s+i&o;
        return(n+e*4+16)%40;
    }
    ```
    Kartu-kartu ini digambar dari sebuah sprite sheet `cards.png` yang berisi 40 kartu.

3.  **Logika Skor/Nilai Kartu:**
    Melalui eksperimen dan pengumpulan data (menggunakan script `collect_data.py`), saya menemukan bahwa "sum of all cards" yang diminta oleh server adalah total nilai dari `e + 1` untuk setiap kartu yang diproses oleh fungsi `h()`. Variabel `e` ini adalah nilai antara 0-9 yang dihitung dari seed `r` sebelum seed tersebut diupdate untuk iterasi berikutnya.

4.  **Level Game:**
    Ada 7 level dengan jumlah kartu yang berbeda-beda:
    - Level 1: 4 kartu
    - Level 2: 8 kartu
    - Level 3: 25 kartu
    - Level 4: 80 kartu
    - Level 5: 50 kartu
    - Level 6: 100 kartu
    - Level 7: 1000 kartu

## Eksploitasi
Karena seed awal diberikan oleh server melalui `/api/start_game` dan setiap jawaban yang benar akan memberikan seed baru untuk level berikutnya, kita bisa mensimulasikan seluruh jalannya permainan secara lokal dan mengirimkan jawaban yang tepat secara otomatis.

Langkah-langkah exploit:
1. Hubungi `/api/start_game` untuk mendapatkan seed awal.
2. Simulasikan fungsi `h()` sebanyak jumlah kartu di level tersebut.
3. Hitung total sum dari `e + 1`.
4. Kirim hasil ke `/api/submit`.
5. Ambil seed baru dari response dan ulangi sampai level 7 selesai.

Script `solve.py` berhasil menyelesaikan semua level dan mendapatkan flag.

## Flag
<FLAG>dalctf{y0vre_re@dy_for_p0k3r}</FLAG>
