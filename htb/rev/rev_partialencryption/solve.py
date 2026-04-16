import angr
import claripy
import logging

# Biar ga berisik log-nya
logging.getLogger('angr').setLevel('ERROR')

def solve():
    # 1. Load Binary (Base address 0x140000000 sesuai info share lu)
    path = "./partialencryption.exe"
    project = angr.Project(path, auto_load_libs=False)

    # 2. Definisikan Flag (Tadi kita itung ada 22 karakter)
    flag_len = 22
    flag_chars = [claripy.BVS(f"char_{i}", 8) for i in range(flag_len)]
    flag = claripy.Concat(*flag_chars)

    # 3. Setup Initial State dengan Flag sebagai Argumen
    # Tambahkan opsi ZERO_FILL biar ga error "unconstrained" kayak kemarin
    state = project.factory.entry_state(
        args=[path, flag],
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        }
    )

    # 4. Tambahin "GDB Findings" kita sebagai Constraints
    # HTB{
    state.add_constraints(flag_chars[0] == ord('H'))
    state.add_constraints(flag_chars[1] == ord('T'))
    state.add_constraints(flag_chars[2] == ord('B'))
    state.add_constraints(flag_chars[3] == ord('{'))
    # Karakter Terakhir
    state.add_constraints(flag_chars[21] == ord('}'))

    # Semua karakter harus printable ASCII
    for c in flag_chars:
        state.add_constraints(c >= 0x20, c <= 0x7e)

    # 5. Simulation Manager
    simgr = project.factory.simulation_manager(state)

    print("[*] Meluncur ke blok memori yang didekripsi (VirtualProtect)...")

    # Kita 'find' ke alamat blok pesan sukses (VirtualProtect kedua yang lu dapet)
    # Kita 'avoid' ke alamat yang manggil "Nope"
    # Alamat ini diambil dari dump assembly x/64i $rax lu tadi
    simgr.explore(
        find=0x14000128d, 
        avoid=0x14000125c
    )

    if simgr.found:
        found_state = simgr.found[0]
        # Ambil nilai flag yang memenuhi syarat
        final_flag = found_state.solver.eval(flag, cast_to=bytes)
        print(f"\n[+] BINGO! Script Berhasil Decrypt Flag: {final_flag.decode()}")
    else:
        print("\n[-] Waduh, script gagal nembus. Cek lagi alamat targetnya.")

if __name__ == "__main__":
    solve()
