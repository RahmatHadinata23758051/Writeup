from pwn import *
import sys

# Konfigurasi target
HOST = 'chal.thjcc.org'
PORT = 12000
BLOCK_SIZE = 16

def check_padding(r, payload):
    """
    Mengirim tebakan ke server dan mengecek validitas padding.
    """
    try:
        # Kirim payload hex langsung (tanpa menunggu prompt)
        r.sendline(payload.hex().encode())
        
        # Baca balasan server
        response = r.recvline().decode('utf-8').strip()
        
        # Jika balasan adalah "BAD", berarti padding salah
        if "BAD" in response:
            return False
            
        # Jika balasan BUKAN "BAD" (misal: "OK", pesan sukses, atau flag), padding valid
        return True
        
    except EOFError:
        # Jika server memutus koneksi tiba-tiba
        log.error("Koneksi terputus! Server mungkin menutup koneksi setelah padding salah.")
        # Jika ini terus terjadi, script membutuhkan arsitektur reconnect-per-byte,
        # tapi umumnya CTF membiarkan koneksi tetap hidup selama panjang input valid.
        return False

def decrypt_block(r, iv, block):
    intermediate = bytearray(BLOCK_SIZE)
    plaintext = bytearray(BLOCK_SIZE)
    
    # Tebak dari byte ke-15 mundur ke byte ke-0
    for i in range(BLOCK_SIZE - 1, -1, -1):
        padding_val = BLOCK_SIZE - i
        match_found = False
        
        # Iterasi dari 0x00 sampai 0xFF
        for guess in range(256):
            fake_iv = bytearray(BLOCK_SIZE)
            
            # Setel byte yang sudah ditebak sebelumnya
            for j in range(BLOCK_SIZE - 1, i, -1):
                fake_iv[j] = intermediate[j] ^ padding_val
                
            fake_iv[i] = guess
            payload = bytes(fake_iv) + block
            
            if check_padding(r, payload):
                # Validasi False Positive untuk byte terakhir (byte ke-15)
                if i == 15:
                    fake_iv[14] ^= 0xFF
                    payload_check = bytes(fake_iv) + block
                    if not check_padding(r, payload_check):
                        continue # False positive, lanjut ke tebakan berikutnya
                
                # Intermediate byte ditemukan
                intermediate[i] = guess ^ padding_val
                plaintext[i] = iv[i] ^ intermediate[i]
                
                char_found = chr(plaintext[i]) if 32 <= plaintext[i] <= 126 else f"\\x{plaintext[i]:02x}"
                log.info(f"Byte [{i:02d}] ditemukan: {char_found}")
                
                match_found = True
                break
                
        if not match_found:
            log.error(f"Gagal mencari byte ke-{i}. Terjadi kesalahan logika atau koneksi.")
            return None
            
    return bytes(plaintext)

def main():
    # Mengatur log pwntools
    context.log_level = 'info'
    
    log.info(f"Menyambungkan ke {HOST}:{PORT}...")
    r = remote(HOST, PORT)
    
    # Ambil token (Ciphertext awal)
    r.recvuntil(b'TOKEN ')
    token_hex = r.recvline().strip().decode('utf-8')
    log.success(f"Token didapatkan: {token_hex}")
    
    token_bytes = bytes.fromhex(token_hex)
    
    # Validasi panjang ciphertext (harus kelipatan 16)
    if len(token_bytes) % BLOCK_SIZE != 0:
        log.error("Panjang token tidak sesuai standar blok AES (bukan kelipatan 16).")
        sys.exit(1)
        
    # Pecah token menjadi blok-blok berukuran 16 byte
    blocks = [token_bytes[i:i+BLOCK_SIZE] for i in range(0, len(token_bytes), BLOCK_SIZE)]
    log.info(f"Total blok: {len(blocks)} (Blok 0 adalah IV)")
    
    flag = b''
    
    # Loop dekripsi untuk setiap blok ciphertext
    for b in range(1, len(blocks)):
        log.info(f"\n--- Memulai dekripsi Blok {b} dari {len(blocks)-1} ---")
        iv = blocks[b-1]
        block = blocks[b]
        
        decrypted_block = decrypt_block(r, iv, block)
        
        if decrypted_block is None:
            log.error("Eksploitasi terhenti.")
            r.close()
            sys.exit(1)
            
        flag += decrypted_block
        
        # Filter karakter non-printable (biasanya ini adalah hasil padding bytes)
        readable_text = ''.join([chr(b) for b in flag if 32 <= b <= 126])
        log.success(f"Plaintext sejauh ini: {readable_text}")

    log.success(f"\n[+] EKSPLOITASI SELESAI. FLAG: {flag.decode('utf-8', errors='ignore')}")
    r.close()

if __name__ == '__main__':
    main()

