import subprocess
import hashlib
import binascii
import json
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Konfigurasi dari hasil analisis binary/pcap
PCAP_FILE = "mosquito.pcap"
TS = 1761146087
USERNAME  = "0367d08072f248a0474784700be2b224084581469eb00ef5e827e7d1782e34ff"
PASSWORD  = "26852622c1f9c54ea24190e5bb33790c7b5442c2c79c4509309f1c2d468fe384"

def decrypt_payload(ct_hex, k, iv):
    try:
        ct_bytes = binascii.unhexlify(ct_hex)
        cipher = AES.new(k, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct_bytes), 16)
        return pt.decode(errors='ignore')
    except Exception:
        return None

def main():
    # 1. Derivasi Key & IV (Logika Go-matching)
    k = hashlib.sha256(USERNAME.encode()).digest()[:16]
    iv = hashlib.sha256(f"{PASSWORD}:{TS}".encode()).digest()[:16]

    print(f"[*] Key: {k.hex()}")
    print(f"[*] IV : {iv.hex()}")
    print(f"[*] Memproses {PCAP_FILE}...\n")

    # 2. Panggil Tshark via Subprocess untuk filter MQTT MsgType 3
    # Kita ambil hex dari paket MQTT
    cmd = [
        "tshark", "-r", PCAP_FILE, 
        "-Y", "mqtt.msgtype == 3", 
        "-T", "fields", "-e", "mqtt.msg"
    ]
    
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, _ = proc.communicate()

    # 3. Parsing dan Dekripsi
    messages = stdout.decode().splitlines()
    found_count = 0

    for msg_hex in messages:
        if not msg_hex: continue
        
        # Convert hex mqtt.msg ke string untuk cari field "data"
        try:
            raw_text = binascii.unhexlify(msg_hex).decode(errors='ignore')
            # Gunakan regex untuk ambil isi di dalam "data":"..."
            match = re.search(r'"data":"([^"]+)"', raw_text)
            
            if match:
                ct_hex = match.group(1)
                result = decrypt_payload(ct_hex, k, iv)
                
                if result:
                    found_count += 1
                    print(f"[Payload {found_count}] {result}")
                    
                    # Berhenti kalau dapet flag yang beneran (format TCP1P atau TCF)
                    if "TCP1P" in result or "TCF" in result:
                        print("\n[!!!] REAL FLAG FOUND!")
        except Exception:
            continue

    if found_count == 0:
        print("[!] Tidak ada payload yang berhasil didekripsi. Cek filter atau TS.")

if __name__ == "__main__":
    main()
