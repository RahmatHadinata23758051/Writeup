Writeup: Thinking Space II (Crypto Challenge - SiebersecCTF)

Tantangan kriptografi Thinking Space II adalah sebuah jebakan (red herring) klasik. Meskipun diberikan file uov.py yang berisi implementasi skema kriptografi Unbalanced Oil and Vinegar (UOV) pasca-kuantum sepanjang ratusan baris, kerentanan sebenarnya tidak ada hubungannya dengan kelemahan matematis algoritma tersebut. Celahnya murni berada pada penanganan tipe data di Python 3.

1. Analisis Kerentanan (Type Confusion)

Mari kita bedah file eksekusi utama chall.py:

thought = b'I am thinking of the flag'
print(pk.hex())

# sign
msg = input('msg: ')
assert msg != thought
print(uov.sign(msg.encode(),sk,pk).hex())


Terdapat dua mekanisme krusial di sini:

Variabel thought dideklarasikan secara eksplisit sebagai tipe data bytes (ditandai dengan prefiks b'').

Program meminta input dari pengguna menggunakan fungsi bawaan input(). Di Python 3, fungsi input() selalu mengembalikan tipe data string (str), terlepas dari apa pun yang kita ketik.

Ketika program menjalankan baris assert msg != thought, Python membandingkan objek str dengan objek bytes. Karena kedua tipe data ini berbeda secara fundamental dalam arsitektur Python 3, perbandingan "I am thinking of the flag" != b"I am thinking of the flag" akan selalu dievaluasi sebagai True.

Berkat type confusion ini, asersi keamanan berhasil dilewati. Setelah lolos, program menjalankan msg.encode() yang mengubah string kita kembali menjadi bytes, yang mana isinya sekarang identik $100\%$ dengan variabel thought. Server pun dengan senang hati membuatkan tanda tangan digital asli untuk kita.

2. Alur Eksploitasi

Eksploitasi dapat dilakukan secara sangat sederhana tanpa perlu membongkar algoritma UOV:

Bypass PoW: Selesaikan Proof of Work standar menggunakan skrip curl yang disediakan.

Kumpulkan Public Key: Simpan Public Key (pk) yang dicetak pertama kali oleh server.

Picu Type Confusion: Saat server meminta input msg: , kita cukup mengetikkan string yang sama persis dengan target:
I am thinking of the flag
Karena input ini adalah string, ia lolos dari blokade assert.

Tangkap Tanda Tangan: Server akan merespons dengan mencetak signature dalam format hex untuk pesan kita.

Verifikasi Flag: Saat server beralih ke blok kode verifikasi dan meminta sig: , kita berikan kembali string hex signature yang baru saja kita dapatkan.

Server memverifikasi tanda tangan tersebut terhadap kunci publik dan pesan thought. Karena valid, server membuka dan memberikan isi flag.txt.

3. Skrip Otomatisasi (solve.py)

Berikut adalah skrip menggunakan pwntools yang secara otomatis membongkar sistem PoW (menggunakan modul subprocess untuk eksekusi bash) dan mengeksploitasi celah type mismatch dalam hitungan detik:

from pwn import *
import subprocess

def solve():
    p = remote('chal.sieberr.live', 20003)

    # 1. Bypass Proof of Work (PoW)
    p.recvuntil(b'Run the following command and input the solution below to solve the proof-of-work:\n')
    cmd = p.recvline().strip().decode()
    
    # Eksekusi command PoW secara otomatis lewat bash
    pow_solution = subprocess.check_output(cmd, shell=True, executable='/bin/bash').strip()
    
    p.sendlineafter(b'> ', pow_solution)
    p.recvuntil(b'Press enter to proceed to the challenge')
    p.sendline(b'')
    
    # 2. Ambil Public Key
    pk_hex = p.recvline().strip()
    
    # 3. Bypass Type Mismatch (Kirim sebagai String/Bytes mentah yang akan dibaca sebagai String oleh input())
    payload = b'I am thinking of the flag'
    p.sendlineafter(b'msg: ', payload)
    
    # 4. Tangkap Tanda Tangan Hasil Penipuan
    sig_hex = p.recvline().strip()
    
    # 5. Kirim kembali Tanda Tangan dan Dapatkan Flag
    p.sendlineafter(b'sig: ', sig_hex)
    flag = p.recvline().strip()
    
    log.success(f"FLAG DITEMUKAN: {flag.decode()}")
    p.close()

if __name__ == '__main__':
    solve()


Flag: sctf{one_who_thinks_all_the_time_has_nothing_to_think_about_except_thoughts} 
