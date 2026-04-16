from pwn import *
from hashlib import sha256

# Matikan debug agar output rapi
context.log_level = 'info'

def hash_node(node):
    return sha256(sha256(node).digest()).digest()

def encode_node(account: str, balance: int):
    return account.encode().ljust(16, b'\x00') + balance.to_bytes(16, byteorder='little')

# 1. Koneksi
io = remote('chall1.lagncra.sh', 13699)

print("[*] Mengambil root bank saat ini...")
io.sendlineafter(b'Select option > ', b'4')
io.recvuntil(b'currently...\r\n')
nodes_hex = io.recvline().strip().decode().split(',')
initial_nodes = [bytes.fromhex(n) for n in nodes_hex if n]

# Hitung Target Root awal
target_root = 0
for n in initial_nodes:
    target_root ^= int.from_bytes(hash_node(n), 'big')

# 2. Siapkan Node Kaya kita
my_name = "pwn_master"
rich_node = encode_node(my_name, 0xcafebeef12345678 + 1337)
h_rich = int.from_bytes(hash_node(rich_node), 'big')

# Kita butuh kombinasi yang menghasilkan target_root ^ h_rich
needed_xor = target_root ^ h_rich

# 3. Membangun Linear Basis
print("[*] Membangun kombinasi Linear Basis...")
basis = [0] * 256
basis_nodes = [set() for _ in range(256)]

for i in range(800):
    junk = encode_node(f"j_{i}", 1) # Saldo 1 agar bisa dideposit manual
    val = int.from_bytes(hash_node(junk), 'big')
    current_set = {junk}
    
    for b in range(255, -1, -1):
        if not ((val >> b) & 1): continue
        if basis[b] == 0:
            basis[b] = val
            basis_nodes[b] = current_set
            break
        val ^= basis[b]
        current_set ^= basis_nodes[b]

res = needed_xor
final_fixers = set()

for b in range(255, -1, -1):
    if (res >> b) & 1:
        res ^= basis[b]
        final_fixers ^= basis_nodes[b]

print(f"[+] Ditemukan {len(final_fixers)} node pembantu.")

# 4. Deposit Bertahap (Bypass Payload Limit)
print("[*] Menyuntikkan helper nodes satu per satu lewat Menu 1...")
# Menggunakan log.progress agar terminal terlihat estetik saat proses
p = log.progress('Depositing nodes')
for idx, n in enumerate(final_fixers):
    p.status(f"{idx + 1}/{len(final_fixers)}")
    # Decode node untuk mendapat param input deposit
    acc = n[:16].decode().strip('\x00')
    bal = int.from_bytes(n[16:32], 'little')
    
    io.sendlineafter(b'Select option > ', b'1')
    io.sendlineafter(b'name > ', acc.encode())
    io.sendlineafter(b'balance > ', str(bal).encode())

p.success("Selesai!")

# Sekarang Root di server = TargetRoot ^ (TargetRoot ^ H_Rich) = H_Rich!
# 5. Lakukan Sync dengan hanya 1 Node!
print("[*] Melakukan Sync Bank (Payload Kecil)...")
payload = rich_node.hex() # Tanpa koma, cuma ngirim 1 node
io.sendlineafter(b'Select option > ', b'2')
io.sendlineafter(b'> ', payload.encode())

# 6. Klaim Flag
print("[*] Klaim Flag...")
io.sendlineafter(b'Select option > ', b'3')
io.sendlineafter(b'name > ', my_name.encode())

# Cetak Flag
print("\n" + "="*30)
print(io.recvall(timeout=5).decode().strip())
print("="*30)
