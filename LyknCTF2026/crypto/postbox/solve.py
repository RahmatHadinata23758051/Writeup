import requests
import sys
import time

URL = "http://ffaf7181-d7f5-481d-a8b8-0edf903c28e1.51.79.140.18.nip.io:8080"
s = requests.Session()

def get_challenge_data():
    print("[*] Meminta token baru dari /login...")
    r = s.get(f"{URL}/login")
    data = r.json()
    return bytes.fromhex(data['iv']), bytes.fromhex(data['ciphertext'])

def is_padding_valid(iv, ct):
    while True:
        try:
            r = s.post(f"{URL}/decrypt", json={"iv": iv.hex(), "ciphertext": ct.hex()}, timeout=5)
            return "bad padding" not in r.text
        except requests.exceptions.RequestException:
            time.sleep(0.5)

def padding_oracle_decrypt(iv, ciphertext):
    blocks = [iv] + [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    plaintext = b""

    print(f"[*] Total blok yang akan didekripsi: {len(blocks) - 1}")

    for block_idx in range(1, len(blocks)):
        prev_block = blocks[block_idx - 1]
        curr_block = blocks[block_idx]
        
        intermediate = bytearray(16)
        block_decrypted = bytearray(16)
        
        print(f"\n[*] Mendekripsi Blok {block_idx}...")
        
        for pad_val in range(1, 17):
            byte_idx = 16 - pad_val
            
            found = False
            for guess in range(256):
                manipulated_prev = bytearray(prev_block)
                
                for i in range(byte_idx + 1, 16):
                    manipulated_prev[i] = intermediate[i] ^ pad_val
                    
                manipulated_prev[byte_idx] = guess ^ pad_val
                
                test_iv = blocks[0] if block_idx > 1 else manipulated_prev
                test_ct = b""
                if block_idx > 1:
                    for i in range(1, block_idx - 1):
                        test_ct += blocks[i]
                    test_ct += manipulated_prev
                    test_ct += curr_block
                else:
                    test_ct = curr_block

                if is_padding_valid(test_iv, test_ct):
                    if pad_val == 1:
                        manipulated_prev[byte_idx - 1] ^= 0x01
                        
                        test_iv_fp = blocks[0] if block_idx > 1 else manipulated_prev
                        test_ct_fp = b""
                        if block_idx > 1:
                            for i in range(1, block_idx - 1):
                                test_ct_fp += blocks[i]
                            test_ct_fp += manipulated_prev
                            test_ct_fp += curr_block
                        else:
                            test_ct_fp = curr_block

                        if not is_padding_valid(test_iv_fp, test_ct_fp):
                            continue 
                            
                    # --- PERBAIKAN FATAL ADA DI SINI ---
                    # Hapus ^ pad_val. Guess sudah merupakan intermediate murni!
                    intermediate[byte_idx] = guess 
                    block_decrypted[byte_idx] = prev_block[byte_idx] ^ intermediate[byte_idx]
                    
                    char_repr = chr(block_decrypted[byte_idx]) if 32 <= block_decrypted[byte_idx] <= 126 else "."
                    print(f"    [+] Byte {byte_idx:02d}: {char_repr!r} (hex: {block_decrypted[byte_idx]:02x})")
                    found = True
                    break
                    
            if not found:
                print(f"    [-] Gagal menemukan byte di index {byte_idx}")
                break
                
        plaintext += block_decrypted
        print(f"[*] Plaintext Sementara: {plaintext}")

    return plaintext

if __name__ == "__main__":
    print("[*] Memulai serangan Padding Oracle Tahan Banting...")
    iv, ciphertext = get_challenge_data()
    
    print(f"[*] IV         : {iv.hex()}")
    print(f"[*] Ciphertext : {ciphertext.hex()}\n")
    
    result = padding_oracle_decrypt(iv, ciphertext)
    
    print("\n" + "="*50)
    print("[+] DEKRIPSI SELESAI!")
    
    try:
        pad_len = result[-1]
        if 1 <= pad_len <= 16:
            unpadded = result[:-pad_len]
            print(f"\n[+] Flag / Data : {unpadded.decode('utf-8', errors='ignore')}")
        else:
            print(f"\n[+] Flag / Data : {result.decode('utf-8', errors='ignore')}")
    except Exception:
        print(f"\n[+] Raw Data    : {result}")
        
    print("="*50)
