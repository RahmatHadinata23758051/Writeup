from pwn import *
import sys

def main():
    context.log_level = 'error'
    print("[*] Mengaktifkan Mode Stealth (1 Koneksi Aman)...")
    
    try:
        io = remote('chals4.apoorvctf.xyz', 1338)
        io.recvuntil(b"> ")
        
        combos = []
        for addr1 in range(16):
            for op1 in range(1, 4):
                for addr2 in range(addr1 + 1, 16):
                    for op2 in range(1, 4):
                        combos.append(((addr1, op1), (addr2, op2)))
        
        print(f"[*] Menyerang {len(combos)} kombinasi Double-Error...")
        
        for i, combo in enumerate(combos):
            addr1, op1 = combo[0]
            addr2, op2 = combo[1]
            
            inst1 = f"{op1:04b}{addr1:04b}"
            inst2 = f"{op2:04b}{addr2:04b}"
            
            # Pipeline payload: kirim 5 command sekaligus dalam 1 paket
            payload = f"WRITE ECR {inst1}\nFLUSHECR\nWRITE ECR {inst2}\nFLUSHECR\nREADOUT\n"
            io.send(payload.encode())
            
            # Lewati 4 prompt pertama balasan dari server
            for _ in range(4):
                io.recvuntil(b"> ")
                
            # Tangkap output dari READOUT
            out = io.recvuntil(b"> ").decode().strip()
            
            if "ERROR ON DECODING" not in out:
                print(f"\n\n[!!!] BINGO! KOREKSI BERHASIL!")
                print(f"[*] Cell {addr1} (Op {op1}) & Cell {addr2} (Op {op2})")
                print("-" * 40)
                print(f"[FLAG OUTPUT]\n{out.replace('>', '').strip()}")
                io.close()
                return
                
            # Loading bar aman biar terminal nggak spam
            if i % 10 == 0:
                sys.stdout.write(f"\r[*] Progress: {i}/{len(combos)} kombinasi diuji...")
                sys.stdout.flush()
                
        print("\n[-] Selesai. Jika gagal, berarti buffer READOUT server tidak otomatis reset.")
        io.close()
        
    except Exception as e:
        print(f"\n[-] Koneksi terputus: {e}")

if __name__ == '__main__':
    main()
