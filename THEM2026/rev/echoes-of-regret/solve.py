import angr
import claripy

# Load binary
proj = angr.Project('./chall', auto_load_libs=False)

# Hook ptrace agar angr menganggap anti-debugging tidak ada (selalu return 0)
proj.hook_symbol('ptrace', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'](resolves_to=0))

# Buat 42 byte simbolik + Null Terminator (\x00) agar strlen() berhenti dengan benar
flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(42)]
flag = claripy.Concat(*flag_chars, claripy.BVV(b'\x00'))

# Setup state dan matikan warning memory
state = proj.factory.entry_state(args=['./chall', flag])
state.options.add(angr.options.UNICORN) # Eksekusi lebih cepat
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

# Batasi pencarian dengan format flag yang sudah pasti
prefix = b"THEM2026{"
for i, c in enumerate(prefix):
    state.solver.add(flag_chars[i] == c)

# Karakter terakhir harus '}'
state.solver.add(flag_chars[41] == b'}'[0])

# Karakter lainnya di rentang printable ASCII
for i in range(9, 41):
    state.solver.add(flag_chars[i] >= 0x20, flag_chars[i] <= 0x7e)

simgr = proj.factory.simgr(state)

# Cari fungsi CRT (0x4013f0) dan hindari blok jebakan exit()/hlt
print("[*] Mengurai cipher rekursif secara simbolik... (tunggu sebentar)")
simgr.explore(find=0x4013f0, avoid=[0x4012cd, 0x401325, 0x4012e2])

if simgr.found:
    found = simgr.found[0]
    
    # Target bytes hasil hitungan SageMath
    target_bytes = b"\xab\xc2RPv\xa2 's\xb7\x9a\xfdr\x96\x05tD~g1z1A\xc3\x0f\xe6'R\xd9\xcfK\x16\x0c\xe3\xca\xd5\xf8z0\xa5\xd2W"
    
    encrypted_buffer = found.memory.load(found.regs.rdi, 42)
    found.solver.add(encrypted_buffer == target_bytes)
    
    print("\n[+] Flag berhasil didekripsi!")
    print(found.solver.eval(flag, cast_to=bytes).decode())
else:
    print("\n[-] Gagal mencapai fungsi CRT. Periksa kembali offset memory.")
