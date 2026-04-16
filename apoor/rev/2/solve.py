from pwn import *

# Pastikan path binary benar
binary_path = './forge'
context.binary = elf = ELF(binary_path)

# Script GDB untuk dikirim ke debugger
# Kita bypass ptrace dan berhenti di offset 0x133e (saat flag ada di R15)
gdb_script = """
catch syscall ptrace
commands
  set $rax = 0
  continue
end

# Breakpoint saat flag sudah didekripsi ke memory/register
# Berdasarkan temuanmu, di sekitar call EVP_EncryptInit_ex
break *($rebase(0x133e))

run

echo \\n\\n--- [ FORGE FLAG CAPTURE ] --- \\n
# Ambil string dari alamat yang ditunjuk R15
x/s $r15
echo \\n------------------------------- \\n
"""

def solve():
    # Jalankan binary di bawah kontrol GDB
    io = gdb.debug([binary_path], gdbscript=gdb_script)
    
    # Karena kita hanya ingin melihat output GDB, kita biarkan interaktif
    io.interactive()

if __name__ == "__main__":
    solve()
